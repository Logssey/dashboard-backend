package com.logssey.reach.l1;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.logssey.reach.l1.dto.ReachWorkloadPageResponse;
import com.logssey.reach.l1.dto.ReachWorkloadResponse;

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

    /**
     * API-07 항목과 스캔 연결. %s는 필터·커서 조건이다.
     * - repository: 파드 이미지에서 @digest, :태그(마지막 / 뒤의 :만), 레지스트리(첫 칸에 . 또는 :가 있거나 localhost)를 뗀 값
     * - revision: 태그. 없으면 null
     * - app: 이 digest의 이미지 대상, 없으면 repository가 같은 이미지 대상(둘 다 최신 대상). 없으면 null
     * - match_scan_id: 이 digest의 이미지 대상에서 PR이 아닌 최신 SUCCEEDED 스캔 (MATCH)
     * - app_scan_id: MATCH가 아닐 때 같은 app 이미지 대상의 기본 범위 스캔 (MISMATCH). 순서는 query 기준 범위와 같다
     * - fresh: 재계산(RECOMPUTE)과 같은 식이라 Finding deployment와 어긋나지 않는다
     */
    private static final String WORKLOADS = """
        WITH base AS (
            SELECT w.workload_id, w.cluster, w.namespace, w.kind, w.name, w.container,
                   w.image_digest, w.ready_replicas, o.observed_at, o.source,
                   o.observed_at > now() - CAST(:fresh AS interval) AS fresh,
                   regexp_replace(regexp_replace(split_part(w.image, '@', 1), ':[^/:]*$', ''),
                                  '^(localhost|[^/]*[.:][^/]*)/', '') AS repository,
                   substring(split_part(w.image, '@', 1) from ':([^/:]*)$') AS revision
            FROM reach_workloads w
            JOIN reach_workload_observations o ON o.cluster = w.cluster AND o.namespace = w.namespace
            WHERE w.cluster = :cluster AND w.namespace IN (:namespaces)
        ), linked AS (
            SELECT b.*,
                   COALESCE(
                       (SELECT t.app FROM reach_targets t
                        WHERE t.target_type = 'IMAGE' AND t.image_digest = b.image_digest
                        ORDER BY t.created_at DESC, t.target_id DESC LIMIT 1),
                       (SELECT t.app FROM reach_targets t
                        WHERE t.target_type = 'IMAGE' AND t.image_repository = b.repository
                        ORDER BY t.created_at DESC, t.target_id DESC LIMIT 1)) AS app,
                   (SELECT s.scan_id FROM reach_scans s JOIN reach_targets t ON t.target_id = s.target_id
                    WHERE t.target_type = 'IMAGE' AND t.image_digest = b.image_digest
                      AND s.scan_status = 'SUCCEEDED' AND s.trigger_type <> 'PR'
                    ORDER BY s.finished_at DESC, s.scan_id DESC LIMIT 1) AS match_scan_id
            FROM base b
        ), matched AS (
            SELECT l.*,
                   CASE WHEN l.fresh THEN 'RUNNING' ELSE 'UNKNOWN' END AS deployment,
                   CASE WHEN l.match_scan_id IS NULL AND l.app IS NOT NULL THEN
                       (SELECT s.scan_id FROM reach_scans s JOIN reach_targets t ON t.target_id = s.target_id
                        WHERE t.target_type = 'IMAGE' AND t.app = l.app
                          AND s.scan_status = 'SUCCEEDED' AND s.trigger_type <> 'PR'
                        ORDER BY s.finished_at DESC, s.scan_id DESC LIMIT 1)
                   END AS app_scan_id
            FROM linked l
        )
        SELECT * FROM matched
        WHERE true %s
        """;

    /** 순서는 명세대로 고정. 커서 행 비교와 칸·순서가 같아야 한다 */
    private static final String WORKLOAD_ORDER = " ORDER BY namespace, name, kind, container, image_digest LIMIT :limit";

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

    /** API-07 observations. namespaces는 허용 목록과 namespace 필터가 겹치는 것(비지 않음) */
    List<ReachWorkloadPageResponse.Observation> observations(String cluster, List<String> namespaces, String fresh) {
        return jdbcClient.sql("""
                SELECT cluster, namespace, observed_at, source,
                       observed_at > now() - CAST(:fresh AS interval) AS fresh
                FROM reach_workload_observations
                WHERE cluster = :cluster AND namespace IN (:namespaces)
                ORDER BY namespace
                """)
                .param("cluster", cluster)
                .param("namespaces", namespaces)
                .param("fresh", fresh)
                .query((rs, i) -> new ReachWorkloadPageResponse.Observation(rs.getString("cluster"),
                        rs.getString("namespace"), rs.getObject("observed_at", OffsetDateTime.class),
                        rs.getString("source"), rs.getBoolean("fresh")))
                .list();
    }

    /** API-07 한 페이지. limit은 페이지 크기 + 1(다음 페이지 확인용) */
    List<ReachWorkloadResponse> workloads(String cluster, List<String> namespaces, String fresh,
                                          ReachWorkloadFilter filter, ReachWorkloadCursor after, int limit) {
        var params = params(cluster, namespaces, fresh, filter);
        var where = new StringBuilder(conditions(filter));
        if (after != null) {
            where.append(" AND (namespace, name, kind, container, image_digest)"
                    + " > (:afterNamespace, :afterName, :afterKind, :afterContainer, :afterDigest)");
            params.put("afterNamespace", after.namespace());
            params.put("afterName", after.name());
            params.put("afterKind", after.kind());
            params.put("afterContainer", after.container());
            params.put("afterDigest", after.digest());
        }
        params.put("limit", limit);
        return jdbcClient.sql(WORKLOADS.formatted(where) + WORKLOAD_ORDER)
                .params(params)
                .query((rs, i) -> workload(rs))
                .list();
    }

    long countWorkloads(String cluster, List<String> namespaces, String fresh, ReachWorkloadFilter filter) {
        return jdbcClient.sql("SELECT count(*) FROM (" + WORKLOADS.formatted(conditions(filter)) + ") c")
                .params(params(cluster, namespaces, fresh, filter))
                .query(Long.class)
                .single();
    }

    private static Map<String, Object> params(String cluster, List<String> namespaces, String fresh,
                                              ReachWorkloadFilter filter) {
        var params = new HashMap<String, Object>();
        params.put("cluster", cluster);
        params.put("namespaces", namespaces);
        params.put("fresh", fresh);
        if (!filter.app().isEmpty()) params.put("app", filter.app());
        if (filter.digest() != null) params.put("digest", filter.digest());
        if (!filter.deployment().isEmpty()) params.put("deployment", filter.deployment());
        return params;
    }

    /** namespace 필터는 Service가 namespaces에 반영해서 여기서는 보지 않는다 */
    private static String conditions(ReachWorkloadFilter filter) {
        var where = new StringBuilder();
        if (!filter.app().isEmpty()) where.append(" AND app IN (:app)");
        if (filter.digest() != null) where.append(" AND image_digest = :digest");
        if (!filter.deployment().isEmpty()) where.append(" AND deployment IN (:deployment)");
        return where.toString();
    }

    private static ReachWorkloadResponse workload(ResultSet rs) throws SQLException {
        long matchScan = rs.getLong("match_scan_id");
        boolean matched = !rs.wasNull();
        long appScan = rs.getLong("app_scan_id");
        boolean appScanned = !rs.wasNull();
        var scanMatch = matched ? new ReachWorkloadResponse.ScanMatch("MATCH", matchScan, "DIGEST")
                : appScanned ? new ReachWorkloadResponse.ScanMatch("MISMATCH", appScan, null)
                : new ReachWorkloadResponse.ScanMatch("NO_SCAN", null, null);
        return new ReachWorkloadResponse(
                rs.getLong("workload_id"),
                rs.getString("cluster"),
                rs.getString("namespace"),
                rs.getString("kind"),
                rs.getString("name"),
                rs.getString("container"),
                rs.getString("app"),
                new ReachWorkloadResponse.Image(rs.getString("repository"), rs.getString("image_digest"),
                        rs.getString("revision")),
                new ReachWorkloadResponse.Replicas(rs.getInt("ready_replicas")),
                rs.getString("deployment"),
                scanMatch,
                rs.getObject("observed_at", OffsetDateTime.class),
                rs.getString("source"));
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
