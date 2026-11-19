package com.logssey.iac.run;

import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

import com.logssey.iac.auth.IacCiCaller;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class IacRunRepository {

    private final JdbcTemplate jdbc;

    public IacRunRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    Optional<Long> adminUserId(String loginId) {
        return jdbc.query("SELECT user_id FROM dashboard_users WHERE login_id = ? AND role = 'ADMIN'",
                (rs, row) -> rs.getLong("user_id"), loginId).stream().findFirst();
    }

    Optional<Repo> enabledRepo(String fullName) {
        return jdbc.query("SELECT repo_id, environment FROM iac_repos WHERE full_name = ? AND enabled",
                (rs, row) -> new Repo(rs.getLong("repo_id"), rs.getString("environment")), fullName)
                .stream().findFirst();
    }

    Optional<Rule> rule(String ruleId) {
        return jdbc.query("""
                SELECT rule_id, default_enforcement, default_severity FROM iac_rules WHERE rule_id = ? AND enabled
                """, (rs, row) -> new Rule(rs.getString("rule_id"), rs.getString("default_enforcement"),
                rs.getString("default_severity")), ruleId).stream().findFirst();
    }

    /** 같은 PR(또는 main 점검)의 run 을 순서대로 등록하도록 잠근다. main 점검은 PR 번호 0 으로 잠근다. */
    void lockPullRequest(long repoId, Integer prNumber) {
        jdbc.query("SELECT pg_advisory_xact_lock(?, ?)", rs -> null, (int) repoId, prNumber == null ? 0 : prNumber);
    }

    long insertRun(long repoId, Integer prNumber, String prTitle, String headSha, String trigger, String status,
                   String verdict, String highestSeverity, Long requestedBy, OffsetDateTime finishedAt) {
        return jdbc.queryForObject("""
                INSERT INTO iac_runs (repo_id, pr_number, pr_title, head_sha, trigger_type, status, verdict,
                                      highest_severity, requested_by_user_id, finished_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                RETURNING run_id
                """, Long.class, repoId, prNumber, prTitle, headSha, trigger, status, verdict, highestSeverity,
                requestedBy, finishedAt);
    }

    /** 같은 PR(또는 main 점검)의 이전 run 을 SUPERSEDED 로 바꾸고, 그 run 의 대기 작업과 남은 plan 을 정리한다. */
    List<Long> supersede(long repoId, Integer prNumber, long newRunId) {
        List<Long> previous = jdbc.queryForList("""
                UPDATE iac_runs SET status = 'SUPERSEDED', superseded_by_run_id = ?,
                                    finished_at = COALESCE(finished_at, now())
                WHERE repo_id = ? AND pr_number IS NOT DISTINCT FROM ? AND run_id <> ? AND status <> 'SUPERSEDED'
                RETURNING run_id
                """, Long.class, newRunId, repoId, prNumber, newRunId);
        if (!previous.isEmpty()) {
            String ids = placeholders(previous);
            jdbc.update("UPDATE iac_jobs SET status = 'CANCELLED', finished_at = now() "
                    + "WHERE status = 'PENDING' AND run_id IN (" + ids + ")", previous.toArray());
            jdbc.update("DELETE FROM iac_plan_payloads WHERE run_id IN (" + ids + ")", previous.toArray());
        }
        return previous;
    }

    void upsertFinding(Rule rule, String source, String environment, String address, String fingerprint,
                       long runId, OffsetDateTime now) {
        jdbc.update("""
                INSERT INTO iac_findings (rule_id, source, enforcement, severity, environment, resource_address,
                                          fingerprint, last_run_id, first_seen_at, last_seen_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (fingerprint) DO UPDATE
                SET last_run_id = EXCLUDED.last_run_id, last_seen_at = EXCLUDED.last_seen_at, status = 'OPEN',
                    version = iac_findings.version + 1
                """, rule.ruleId(), source, rule.enforcement(), rule.severity(), environment, address, fingerprint,
                runId, now, now);
    }

    /** 이 PR(또는 main 점검)의 이전 run 에서 열렸던 같은 출처의 발견 건 중 이번에 안 나온 것은 고쳐진 것으로 본다. */
    int fixMissing(long repoId, Integer prNumber, String source, Collection<String> seenFingerprints) {
        String notSeen = seenFingerprints.isEmpty() ? "" : " AND f.fingerprint NOT IN (" + placeholders(seenFingerprints) + ")";
        Object[] args = new Object[3 + seenFingerprints.size()];
        args[0] = source;
        args[1] = repoId;
        args[2] = prNumber;
        int i = 3;
        for (String fingerprint : seenFingerprints) args[i++] = fingerprint;
        return jdbc.update("""
                UPDATE iac_findings f SET status = 'FIXED', version = f.version + 1
                FROM iac_runs r
                WHERE f.last_run_id = r.run_id AND f.status = 'OPEN' AND f.source = ?
                  AND r.repo_id = ? AND r.pr_number IS NOT DISTINCT FROM ?
                """ + notSeen, args);
    }

    Optional<RunRow> lockRun(long runId) {
        return jdbc.query("SELECT run_id, status, trigger_type FROM iac_runs WHERE run_id = ? FOR UPDATE",
                (rs, row) -> new RunRow(rs.getLong("run_id"), rs.getString("status"), rs.getString("trigger_type")),
                runId).stream().findFirst();
    }

    void storePlan(long runId, byte[] gzip, OffsetDateTime expiresAt) {
        jdbc.update("""
                INSERT INTO iac_plan_payloads (run_id, content, size_bytes, expires_at) VALUES (?, ?, ?, ?)
                ON CONFLICT (run_id) DO UPDATE
                SET content = EXCLUDED.content, size_bytes = EXCLUDED.size_bytes,
                    received_at = now(), expires_at = EXCLUDED.expires_at
                """, runId, gzip, gzip.length, expiresAt);
    }

    void markAnalyzing(long runId) {
        jdbc.update("UPDATE iac_runs SET status = 'ANALYZING' WHERE run_id = ?", runId);
    }

    /** PR run 은 경로 분석(ANALYZE_RUN), main 점검 run 은 드리프트 점검(CHECK_DRIFT). */
    void enqueueAnalysis(long runId, boolean push, Long requestedBy) {
        jdbc.update("""
                INSERT INTO iac_jobs (kind, trigger_type, run_id, requested_by_user_id)
                VALUES (?, ?, ?, ?)
                """, push ? "CHECK_DRIFT" : "ANALYZE_RUN", push ? "SCHEDULED" : "PR", runId, requestedBy);
    }

    Optional<IacRunStatusResponse> status(long runId) {
        return jdbc.query("""
                SELECT r.run_id, p.full_name, r.pr_number, r.head_sha, r.status, r.verdict, r.highest_severity,
                       r.graph_as_of, r.created_at, r.finished_at
                FROM iac_runs r JOIN iac_repos p ON p.repo_id = r.repo_id
                WHERE r.run_id = ?
                """, (rs, row) -> new IacRunStatusResponse(rs.getLong("run_id"), rs.getString("full_name"),
                rs.getObject("pr_number", Integer.class), rs.getString("head_sha"), rs.getString("status"),
                rs.getString("verdict"), rs.getString("highest_severity"),
                rs.getObject("graph_as_of", OffsetDateTime.class), rs.getObject("created_at", OffsetDateTime.class),
                rs.getObject("finished_at", OffsetDateTime.class)), runId).stream().findFirst();
    }

    /** 사용자가 없으면(GitHub Actions OIDC) CI 로 남긴다 */
    void audit(Long actorUserId, String entityType, long entityId, String eventType, String afterSafeJson) {
        jdbc.update("""
                INSERT INTO iac_audit_events (actor_kind, actor_user_id, entity_type, entity_id, event_type, after_safe)
                VALUES (?, ?, ?, ?, ?, ?::jsonb)
                """, actorUserId == null ? "CI" : "USER", actorUserId, entityType, entityId, eventType, afterSafeJson);
    }

    /** run 이 속한 레포 이름과 실행 종류 (CI 토큰이 다룰 수 있는 run 인지 볼 때) */
    Optional<IacCiCaller> runOwner(long runId) {
        return jdbc.query("""
                SELECT r.full_name, run.trigger_type FROM iac_runs run JOIN iac_repos r ON r.repo_id = run.repo_id
                WHERE run.run_id = ?
                """, (rs, row) -> new IacCiCaller(rs.getString("full_name"), rs.getString("trigger_type")), runId)
                .stream().findFirst();
    }

    OffsetDateTime databaseNow() {
        return jdbc.queryForObject("SELECT now()", OffsetDateTime.class);
    }

    private static String placeholders(Collection<?> values) {
        return String.join(",", java.util.Collections.nCopies(values.size(), "?"));
    }

    record Repo(long repoId, String environment) {
    }

    record Rule(String ruleId, String enforcement, String severity) {
    }

    record RunRow(long runId, String status, String trigger) {
    }
}
