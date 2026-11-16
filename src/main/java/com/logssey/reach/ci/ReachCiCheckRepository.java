package com.logssey.reach.ci;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.logssey.reach.ci.auth.ReachCiAccess;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Reach CI 검사 SQL (API-12). 대상·스캔·검사를 만들고, 결과 조회 때 새 Finding을 센다 */
@Repository
public class ReachCiCheckRepository {

    private final JdbcClient jdbcClient;

    public ReachCiCheckRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    Optional<Long> adminUserId(String loginId) {
        return jdbcClient.sql("SELECT user_id FROM dashboard_users WHERE login_id = :loginId AND role = 'ADMIN'")
                .param("loginId", loginId)
                .query(Long.class)
                .optional();
    }

    /**
     * 같은 호출 주체·키의 요청을 이 트랜잭션이 끝날 때까지 한 줄로 세운다 (명세 2-7: 동시에 두 번 오면 하나만 처리).
     * 두 번째 요청은 첫 요청이 커밋한 검사를 찾아 같은 응답을 받는다
     */
    void lockIdempotencyKey(String scope, String key) {
        jdbcClient.sql("SELECT pg_advisory_xact_lock(hashtextextended(:lockKey, 0))")
                .param("lockKey", "reach-ci-check\n" + scope + "\n" + key)
                .query((rs, i) -> true)   // 반환 칸이 void라 읽지 않는다
                .single();
    }

    record KeyedCheck(long checkId, String requestHash) {}

    Optional<KeyedCheck> checkByKey(String scope, String key) {
        return jdbcClient.sql("""
                        SELECT check_id, request_hash FROM reach_ci_checks
                        WHERE idempotency_scope = :scope AND idempotency_key = :key
                        """)
                .param("scope", scope)
                .param("key", key)
                .query((rs, i) -> new KeyedCheck(rs.getLong("check_id"), rs.getString("request_hash")))
                .optional();
    }

    record TargetRow(long id, String app) {}

    /**
     * 대상을 (저장소, digest) 또는 (레포, 하위 경로, 커밋)으로 찾고 없으면 만든다 (DB 스키마 4절 1단계).
     * 동시에 같은 대상을 만들면 한쪽은 ON CONFLICT로 넘어가고 아래 SELECT가 먼저 만든 행을 찾는다
     */
    TargetRow findOrCreateTarget(ReachTargets.Resolved t) {
        boolean image = "IMAGE".equals(t.type());
        jdbcClient.sql(image
                        ? """
                          INSERT INTO reach_targets (target_type, app, image_repository, image_digest, display_name)
                          VALUES ('IMAGE', :app, :imageRepository, :imageDigest, :displayName)
                          ON CONFLICT (image_repository, image_digest) WHERE target_type = 'IMAGE' DO NOTHING
                          """
                        : """
                          INSERT INTO reach_targets (target_type, app, repo_name, repo_path, repo_commit, display_name)
                          VALUES ('REPO', :app, :repoName, :repoPath, :repoCommit, :displayName)
                          ON CONFLICT (repo_name, COALESCE(repo_path, ''), repo_commit) WHERE target_type = 'REPO' DO NOTHING
                          """)
                .paramSource(t)   // record 칸 이름(app, imageRepository …)으로 :이름을 채운다
                .update();
        return jdbcClient.sql(image
                        ? """
                          SELECT target_id, app FROM reach_targets
                          WHERE target_type = 'IMAGE' AND image_repository = :imageRepository AND image_digest = :imageDigest
                          """
                        : """
                          SELECT target_id, app FROM reach_targets
                          WHERE target_type = 'REPO' AND repo_name = :repoName
                            AND COALESCE(repo_path, '') = COALESCE(:repoPath, '') AND repo_commit = :repoCommit
                          """)
                .paramSource(t)
                .query((rs, i) -> new TargetRow(rs.getLong("target_id"), rs.getString("app")))
                .single();
    }

    record ScanRow(long targetId, String scanStatus) {}

    Optional<ScanRow> scan(long scanId) {
        return jdbcClient.sql("SELECT target_id, scan_status FROM reach_scans WHERE scan_id = :scanId")
                .param("scanId", scanId)
                .query((rs, i) -> new ScanRow(rs.getLong("target_id"), rs.getString("scan_status")))
                .optional();
    }

    /** 새 스캔은 QUEUED. 러너가 결과를 올리면(API-13) RUNNING을 거쳐 끝난다 */
    /** CI 토큰이 만든 스캔. 재검사는 사람만 해서 rescan_of는 없다 */
    long insertCiScan(long targetId, String trigger, String repository, String subject) {
        return jdbcClient.sql("""
                        INSERT INTO reach_scans (target_id, trigger_type, requested_by_kind,
                                                 requested_by_repository, requested_by_subject)
                        VALUES (:targetId, :trigger, 'CI', :repository, :subject)
                        RETURNING scan_id
                        """)
                .param("targetId", targetId)
                .param("trigger", trigger)
                .param("repository", repository)
                .param("subject", subject)
                .query(Long.class)
                .single();
    }

    /** 검사를 만든 주체 (USER:<id>, CI:<repository>). 검사가 없으면 빈 값 */
    /** 검사를 만든 주체와 레포. CI 토큰이 이 검사를 보고 올릴 수 있는지(ReachCiAccess) 정한다 */
    Optional<ReachCiAccess.CheckOwner> checkOwner(long checkId) {
        return jdbcClient.sql("SELECT idempotency_scope, mode, repository FROM reach_ci_checks WHERE check_id = :checkId")
                .param("checkId", checkId)
                .query((rs, n) -> new ReachCiAccess.CheckOwner(rs.getString("idempotency_scope"), rs.getString("mode"),
                        rs.getString("repository")))
                .optional();
    }

    long insertScan(long targetId, String trigger, Long rescanOf, long userId) {
        return jdbcClient.sql("""
                        INSERT INTO reach_scans (target_id, trigger_type, rescan_of_scan_id,
                                                 requested_by_kind, requested_by_user_id)
                        VALUES (:targetId, :trigger, :rescanOf, 'USER', :userId)
                        RETURNING scan_id
                        """)
                .param("targetId", targetId)
                .param("trigger", trigger)
                .param("rescanOf", rescanOf)
                .param("userId", userId)
                .query(Long.class)
                .single();
    }

    /** 검사 한 행. options는 API-01이 채우고 API-12는 빈 객체다 */
    record NewCheck(long scanId, String mode, String repository, String headCommit, Integer prNumber,
                    String prBaseRef, String prHeadRef, String policy, Long baselineScanId, String options,
                    String idempotencyScope, String idempotencyKey, String requestHash) {}

    long insertCheck(NewCheck check) {
        return jdbcClient.sql("""
                        INSERT INTO reach_ci_checks (scan_id, mode, repository, head_commit, pr_number, pr_base_ref,
                                                     pr_head_ref, policy, baseline_scan_id, options,
                                                     idempotency_scope, idempotency_key, request_hash)
                        VALUES (:scanId, :mode, :repository, :headCommit, :prNumber, :prBaseRef,
                                :prHeadRef, :policy, :baselineScanId, CAST(:options AS jsonb),
                                :idempotencyScope, :idempotencyKey, :requestHash)
                        RETURNING check_id
                        """)
                .paramSource(check)
                .query(Long.class)
                .single();
    }

    /** 검사 + 그 스캔의 상태와 끝난 시각 */
    record CheckRow(long id, String mode, String repository, String headCommit, Integer prNumber,
                    String prBaseRef, String prHeadRef, long scanId, String scanStatus, String policy,
                    Long baselineScanId, OffsetDateTime createdAt, OffsetDateTime finishedAt) {}

    Optional<CheckRow> check(long checkId) {
        return jdbcClient.sql(CHECKS + " WHERE c.check_id = :checkId")
                .param("checkId", checkId)
                .query(this::checkRow)
                .optional();
    }

    /** 목록·개수가 같이 쓰는 FROM. 상태는 스캔에 있다 */
    private static final String CHECKS = """
            SELECT c.check_id, c.mode, c.repository, c.head_commit, c.pr_number, c.pr_base_ref,
                   c.pr_head_ref, c.scan_id, s.scan_status, c.policy, c.baseline_scan_id,
                   c.created_at, s.finished_at
            FROM reach_ci_checks c
            JOIN reach_scans s ON s.scan_id = c.scan_id""";

    /** CI 검사 목록. 최신(검사 id 큰) 순, afterId보다 작은 것부터 limit개 */
    List<CheckRow> checks(ReachCiCheckFilter filter, Long afterId, int limit) {
        var where = where(filter, afterId);
        var params = new HashMap<>(where.params());
        params.put("limit", limit);
        return jdbcClient.sql(CHECKS + where.sql() + " ORDER BY c.check_id DESC LIMIT :limit")
                .params(params)
                .query(this::checkRow)
                .list();
    }

    long countChecks(ReachCiCheckFilter filter) {
        var where = where(filter, null);
        return jdbcClient.sql("SELECT count(*) FROM (" + CHECKS + where.sql() + ") c")
                .params(where.params())
                .query(Long.class)
                .single();
    }

    private record Where(String sql, Map<String, Object> params) {}

    /**
     * repository는 대소문자 무시로, 저장된 값이 소유자를 붙였든(Logssey/service-backend) 아니든 이름으로 맞춘다.
     * 빈 목록인 칸은 거르지 않는다(빈 IN ()은 SQL 오류)
     */
    private static Where where(ReachCiCheckFilter filter, Long afterId) {
        var conditions = new ArrayList<String>();
        var params = new HashMap<String, Object>();
        if (filter.repository() != null) {
            conditions.add("lower(substring(c.repository FROM '[^/]*$')) = lower(:repository)");
            params.put("repository", filter.repositoryName());
        }
        if (!filter.mode().isEmpty()) {
            conditions.add("c.mode IN (:modes)");
            params.put("modes", filter.mode());
        }
        if (!filter.scanStatus().isEmpty()) {
            conditions.add("s.scan_status IN (:statuses)");
            params.put("statuses", filter.scanStatus());
        }
        if (afterId != null) {
            conditions.add("c.check_id < :afterId");
            params.put("afterId", afterId);
        }
        return new Where(conditions.isEmpty() ? "" : " WHERE " + String.join(" AND ", conditions), params);
    }

    /** NULL일 수 있는 숫자는 getObject로 읽는다. getInt·getLong은 NULL을 0으로 준다 */
    private CheckRow checkRow(ResultSet rs, int rowNum) throws SQLException {
        return new CheckRow(rs.getLong("check_id"), rs.getString("mode"), rs.getString("repository"),
                rs.getString("head_commit"), rs.getObject("pr_number", Integer.class), rs.getString("pr_base_ref"),
                rs.getString("pr_head_ref"), rs.getLong("scan_id"), rs.getString("scan_status"),
                rs.getString("policy"), rs.getObject("baseline_scan_id", Long.class),
                rs.getObject("created_at", OffsetDateTime.class), rs.getObject("finished_at", OffsetDateTime.class));
    }

    record NewFindingRow(String status, String severity, long count) {}

    /**
     * 이 스캔의 도구 판정 중 기준 스캔에 없던 purl × CVE를 상태·심각도별로 센다 (명세 6-2 "새 Finding").
     * 기준 스캔은 다른 대상(예: main 커밋)일 수 있어 Finding id가 아니라 purl과 CVE로 비교한다.
     * 기준 스캔이 없으면(NULL) 아래 NOT EXISTS가 늘 참이라 모두 새 것이다. MANUAL(사람 판정)은 스캔 결과가 아니라 뺀다
     */
    List<NewFindingRow> newFindingCounts(long scanId, Long baselineScanId) {
        return jdbcClient.sql("""
                        SELECT v.status, f.severity, count(*) AS n
                        FROM reach_verdicts v
                        JOIN reach_findings f ON f.finding_id = v.finding_id
                        WHERE v.scan_id = :scanId AND v.method IS DISTINCT FROM 'MANUAL'
                          AND NOT EXISTS (
                              SELECT 1 FROM reach_verdicts bv
                              JOIN reach_findings bf ON bf.finding_id = bv.finding_id
                              WHERE bv.scan_id = :baselineScanId AND bv.method IS DISTINCT FROM 'MANUAL'
                                AND bf.purl = f.purl AND bf.vulnerability_id = f.vulnerability_id)
                        GROUP BY v.status, f.severity
                        """)
                .param("scanId", scanId)
                .param("baselineScanId", baselineScanId)
                .query((rs, i) -> new NewFindingRow(rs.getString("status"), rs.getString("severity"), rs.getLong("n")))
                .list();
    }
}
