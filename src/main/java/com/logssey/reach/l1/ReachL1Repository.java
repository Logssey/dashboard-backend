package com.logssey.reach.l1;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * Reach L1 워크로드.
 * 업로드는 (cluster, namespace) 단위로 통째로 바꾸고, Finding deployment를 다시 계산한다.
 */
@Repository
public class ReachL1Repository {

    /**
     * 이미지 대상 Finding의 deployment. 신선한 조회에서 그 digest가 보이면 RUNNING,
     * 허용 네임스페이스가 모두 신선하게, 그리고 대상이 생긴 뒤에 조회됐는데 없으면 NOT_RUNNING, 그 밖은 UNKNOWN (PRD FR-04).
     * 값이 바뀐 행만 고친다. %s는 대상 하나만 다시 계산할 때의 조건이다
     */
    private static final String RECOMPUTE = """
        UPDATE reach_findings f
        SET deployment = c.next_deployment
        FROM (
            SELECT f2.finding_id,
                   CASE
                       WHEN EXISTS (SELECT 1 FROM reach_workloads w
                                    JOIN reach_workload_observations o
                                      ON o.cluster = w.cluster AND o.namespace = w.namespace
                                    WHERE w.image_digest = t.image_digest
                                      AND o.cluster = :cluster AND o.namespace IN (:namespaces)
                                      AND o.observed_at > now() - CAST(:fresh AS interval)) THEN 'RUNNING'
                       WHEN (SELECT count(*) FROM reach_workload_observations o
                             WHERE o.cluster = :cluster AND o.namespace IN (:namespaces)
                               AND o.observed_at > now() - CAST(:fresh AS interval)
                               AND o.observed_at > t.created_at) = :namespaceCount THEN 'NOT_RUNNING'
                       ELSE 'UNKNOWN'
                   END AS next_deployment
            FROM reach_findings f2
            JOIN reach_targets t ON t.target_id = f2.target_id
            WHERE t.target_type = 'IMAGE' %s
        ) c
        WHERE f.finding_id = c.finding_id
          AND f.deployment IS DISTINCT FROM c.next_deployment
        """;

    private final JdbcClient jdbcClient;

    public ReachL1Repository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    Optional<Long> adminUserId(String loginId) {
        return jdbcClient.sql("SELECT user_id FROM dashboard_users WHERE login_id = :loginId AND role = 'ADMIN'")
                .param("loginId", loginId)
                .query(Long.class)
                .optional();
    }

    /** 재계산(업로드·6시간마다 작업·API-13 업로드)은 한 번에 하나만. 트랜잭션이 끝나면 풀린다 */
    void lockRecompute() {
        jdbcClient.sql("SELECT pg_advisory_xact_lock(hashtextextended('reach-l1-recompute', 0))")
                .query((rs, i) -> true)   // 반환 칸이 void라 읽지 않는다
                .single();
    }

    /**
     * 네임스페이스의 마지막 조회. 지우지 않고 덮어써서 조회 행이 잠깐이라도 없어지지 않게 한다.
     * 저장된 것보다 오래된 observedAt이면 아무것도 바꾸지 않고 0을 돌려준다(같은 시각은 덮어쓴다)
     */
    int saveObservation(String cluster, String namespace, OffsetDateTime observedAt, String source, String reportedBy) {
        return jdbcClient.sql("""
                INSERT INTO reach_workload_observations (cluster, namespace, observed_at, source, reported_by)
                VALUES (:cluster, :namespace, :observedAt, :source, :reportedBy)
                ON CONFLICT (cluster, namespace) DO UPDATE
                SET observed_at = EXCLUDED.observed_at, received_at = now(),
                    source = EXCLUDED.source, reported_by = EXCLUDED.reported_by
                WHERE reach_workload_observations.observed_at <= EXCLUDED.observed_at
                """)
                .param("cluster", cluster)
                .param("namespace", namespace)
                .param("observedAt", observedAt)
                .param("source", source)
                .param("reportedBy", reportedBy)
                .update();
    }

    void deleteWorkloads(String cluster, String namespace) {
        jdbcClient.sql("DELETE FROM reach_workloads WHERE cluster = :cluster AND namespace = :namespace")
                .param("cluster", cluster)
                .param("namespace", namespace)
                .update();
    }

    /** 컨테이너 하나 = 한 행 */
    void insertWorkload(String cluster, String namespace, String kind, String name,
                        String container, String image, String imageDigest, int readyReplicas) {
        jdbcClient.sql("""
                INSERT INTO reach_workloads (cluster, namespace, kind, name, container, image, image_digest, ready_replicas)
                VALUES (:cluster, :namespace, :kind, :name, :container, :image, :imageDigest, :readyReplicas)
                """)
                .param("cluster", cluster)
                .param("namespace", namespace)
                .param("kind", kind)
                .param("name", name)
                .param("container", container)
                .param("image", image)
                .param("imageDigest", imageDigest)
                .param("readyReplicas", readyReplicas)
                .update();
    }

    /** targetId가 없으면 모든 이미지 대상. 바뀐 행 수를 돌려준다 */
    int recompute(String cluster, List<String> namespaces, String fresh, Long targetId) {
        var spec = jdbcClient.sql(RECOMPUTE.formatted(targetId == null ? "" : "AND t.target_id = :targetId"))
                .param("cluster", cluster)
                .param("namespaces", namespaces)          // List를 넘기면 IN (...)으로 펼쳐 준다. 빈 리스트면 SQL 오류
                .param("namespaceCount", namespaces.size())
                .param("fresh", fresh);                   // "48 hours"
        if (targetId != null) {
            spec = spec.param("targetId", targetId);
        }
        return spec.update();
    }
}
