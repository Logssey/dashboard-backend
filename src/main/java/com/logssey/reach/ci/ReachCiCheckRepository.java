package com.logssey.reach.ci;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
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

    record KeyedCheck(long checkId, String requestHash, String scanStatus) {}

    Optional<KeyedCheck> checkByKey(String scope, String key) {
        return jdbcClient.sql("""
                        SELECT c.check_id, c.request_hash, s.scan_status FROM reach_ci_checks c
                        JOIN reach_scans s ON s.scan_id = c.scan_id
                        WHERE c.idempotency_scope = :scope AND c.idempotency_key = :key
                        """)
                .param("scope", scope)
                .param("key", key)
                .query((rs, i) -> new KeyedCheck(rs.getLong("check_id"), rs.getString("request_hash"),
                        rs.getString("scan_status")))
                .optional();
    }

    /**
     * 실패한 검사의 멱등 키를 놓아 준다. 같은 키로 새 검사를 만들 수 있게 키를 released-<검사 ID>로 바꾼다.
     * 검사·스캔·실패 사유는 그대로 남는다 (명세 2-7)
     */
    void releaseKey(long checkId) {
        jdbcClient.sql("UPDATE reach_ci_checks SET idempotency_key = 'released-' || check_id WHERE check_id = :checkId")
                .param("checkId", checkId)
                .update();
    }

    /**
     * 결과가 오지 않은 채 오래된 스캔을 실패로 끝낸다 (러너가 취소·시간 초과로 실패 묶음도 못 올린 경우).
     * CI 검사가 있는 스캔만 본다. 끝낸 스캔 수를 준다
     */
    int failStale(Duration olderThan) {
        return jdbcClient.sql("""
                        UPDATE reach_scans s
                        SET scan_status = 'FAILED', finished_at = now(), failure_code = 'RUNNER_NO_RESULT',
                            failure_message = :message
                        FROM reach_ci_checks c
                        WHERE c.scan_id = s.scan_id AND s.scan_status IN ('QUEUED', 'RUNNING')
                          AND s.created_at < now() - make_interval(secs => :seconds)
                        """)
                .param("message", "No result from the runner within " + olderThan.toMinutes()
                        + " minutes (cancelled, timed out or never started)")
                .param("seconds", (double) olderThan.toSeconds())
                .update();
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
        return jdbcClient.sql("""
                        SELECT idempotency_scope, mode, repository, pr_number FROM reach_ci_checks WHERE check_id = :checkId
                        """)
                .param("checkId", checkId)
                .query((rs, n) -> new ReachCiAccess.CheckOwner(rs.getString("idempotency_scope"), rs.getString("mode"),
                        rs.getString("repository"), rs.getObject("pr_number", Integer.class)))
                .optional();
    }

    /** 대시보드 예약 작업이 만든 스캔 (하루 1번 재대조, requested_by_kind SYSTEM) */
    long insertSystemScan(long targetId, String trigger, long rescanOf) {
        return jdbcClient.sql("""
                        INSERT INTO reach_scans (target_id, trigger_type, rescan_of_scan_id, requested_by_kind)
                        VALUES (:targetId, :trigger, :rescanOf, 'SYSTEM')
                        RETURNING scan_id
                        """)
                .param("targetId", targetId)
                .param("trigger", trigger)
                .param("rescanOf", rescanOf)
                .query(Long.class)
                .single();
    }

    /** 재대조할 스캔의 대상. 러너를 띄울 레포와 inputs를 정한다 */
    Optional<ReachTargets.Resolved> rescanTarget(long scanId) {
        return jdbcClient.sql("""
                        SELECT t.target_type, t.app, t.repo_name, t.repo_path, t.repo_commit, t.image_repository,
                               t.image_digest, t.display_name
                        FROM reach_scans s JOIN reach_targets t ON t.target_id = s.target_id
                        WHERE s.scan_id = :scanId
                        """)
                .param("scanId", scanId)
                .query((rs, i) -> new ReachTargets.Resolved(rs.getString("target_type"), rs.getString("app"),
                        rs.getString("repo_name"), rs.getString("repo_path"), rs.getString("repo_commit"),
                        rs.getString("image_repository"), rs.getString("image_digest"), rs.getString("display_name")))
                .optional();
    }

    /** 검사의 스캔이 재대조면 원래 스캔에 보관한 SBOM(gzip). 재대조가 아니거나 보관한 것이 없으면 빈 값 */
    Optional<byte[]> rescanSbom(long checkId) {
        return jdbcClient.sql("""
                        SELECT b.content_gzip
                        FROM reach_ci_checks c
                        JOIN reach_scans s ON s.scan_id = c.scan_id
                        JOIN reach_sboms b ON b.scan_id = s.rescan_of_scan_id
                        WHERE c.check_id = :checkId
                        """)
                .param("checkId", checkId)
                .query((rs, i) -> rs.getBytes("content_gzip"))
                .optional();
    }

    /**
     * 검사의 스캔이 재대조면 그 대상(이미지)에 보관한 가장 새 L3 실행 기록(tar.xz).
     * 재대조가 아니거나 보관한 것이 없으면(앱을 띄워 본 적 없는 이미지, 정리된 기록) 빈 값
     */
    Optional<byte[]> rescanL3Record(long checkId) {
        return jdbcClient.sql("""
                        SELECT r.content
                        FROM reach_ci_checks c
                        JOIN reach_scans s ON s.scan_id = c.scan_id AND s.rescan_of_scan_id IS NOT NULL
                        JOIN reach_scans o ON o.target_id = s.target_id
                        JOIN reach_l3_records r ON r.scan_id = o.scan_id
                        WHERE c.check_id = :checkId
                        ORDER BY r.scan_id DESC
                        LIMIT 1
                        """)
                .param("checkId", checkId)
                .query((rs, i) -> rs.getBytes("content"))
                .optional();
    }

    boolean checkExists(long checkId) {
        return jdbcClient.sql("SELECT count(*) FROM reach_ci_checks WHERE check_id = :checkId")
                .param("checkId", checkId)
                .query(Long.class)
                .single() > 0;
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
     * 판정의 위험 순위. REACHABLE > UNKNOWN = NOT_ANALYZED > UNREACHABLE.
     * UNKNOWN과 NOT_ANALYZED는 둘 다 "안전하다고 확인하지 못함"이라 같은 순위로 본다
     */
    private static String rank(String alias) {
        return "CASE " + alias + ".status WHEN 'REACHABLE' THEN 3 WHEN 'UNREACHABLE' THEN 1 ELSE 2 END";
    }

    /**
     * 이 스캔의 도구 판정 중 "새 Finding"을 상태·심각도별로 센다 (명세 6-2).
     * 새 Finding = 기준 스캔에 없던 purl × CVE, 또는 기준 스캔에서는 판정이 더 낮던 것.
     * 라이브러리는 그대로인데 코드가 바뀌어 UNREACHABLE → REACHABLE이 된 것을 잡으려는 것이다.
     * 기준에서 이미 같은 순위 이상이던 것(이미 있던 위험)은 세지 않는다. PR을 막는 이유가 되지 않는다.
     * 기준 스캔은 다른 대상(예: 운영 이미지)일 수 있어 Finding id가 아니라 purl과 CVE로 비교한다.
     * purl은 한정자(?…)와 하위 경로(#…)를 떼고 비교한다. 레포 SBOM(cdxgen)은 pkg:maven/g/a@v?type=jar,
     * 이미지 스캔(Trivy)은 pkg:maven/g/a@v로 같은 패키지를 다르게 적어서다.
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
                                AND split_part(split_part(bf.purl, '#', 1), '?', 1)
                                    = split_part(split_part(f.purl, '#', 1), '?', 1)
                                AND bf.vulnerability_id = f.vulnerability_id
                                AND %s >= %s)
                        GROUP BY v.status, f.severity
                        """.formatted(rank("bv"), rank("v")))
                .param("scanId", scanId)
                .param("baselineScanId", baselineScanId)
                .query((rs, i) -> new NewFindingRow(rs.getString("status"), rs.getString("severity"), rs.getLong("n")))
                .list();
    }
}
