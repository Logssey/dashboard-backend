package com.logssey.iacworker.analysis;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class AnalyzeRunRepository {

    private final JdbcTemplate jdbc;

    public AnalyzeRunRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    Optional<String> runStatus(long runId) {
        return jdbc.queryForList("SELECT status FROM iac_runs WHERE run_id = ?", String.class, runId).stream().findFirst();
    }

    Optional<byte[]> plan(long runId) {
        return jdbc.query("SELECT content FROM iac_plan_payloads WHERE run_id = ?", (rs, row) -> rs.getBytes("content"),
                runId).stream().findFirst();
    }

    java.util.Set<String> tfstateArns() {
        return new java.util.HashSet<>(jdbc.queryForList(
                "SELECT arn FROM iac_data_assets WHERE kind = 'TFSTATE'", String.class));
    }

    OffsetDateTime graphAsOf() {
        return jdbc.queryForObject("""
                SELECT max(finished_at) FROM iac_jobs WHERE kind = 'COLLECT_GRAPH' AND status = 'SUCCEEDED'
                """, OffsetDateTime.class);
    }

    void clearChanges(long runId) {
        jdbc.update("DELETE FROM iac_run_path_changes WHERE run_id = ?", runId);
    }

    void insertChange(long runId, AnalysisEngine.Change change, String hopsJson, String evidenceJson) {
        jdbc.update("""
                INSERT INTO iac_run_path_changes (run_id, change, rule_id, path_id, path_fingerprint, tier, severity, hops,
                                                  cause_address, evidence)
                VALUES (?, ?, ?, (SELECT path_id FROM iac_attack_paths WHERE fingerprint = ? AND ? <> 'ADDED'),
                        ?, ?, ?, ?::jsonb, ?, ?::jsonb)
                """, runId, change.change(), change.ruleId(), change.fingerprint(), change.change(), change.fingerprint(),
                change.tier(), change.severity(), hopsJson, change.cause() == null ? null : change.cause().address(),
                evidenceJson);
    }

    /**
     * PR 의 경로 결과(ADDED·SHORTENED)를 발견 건으로도 남긴다. 지문은 규칙 + 경로 지문 + 레포 + PR 번호.
     * 같은 PR 의 다음 분석에서 다시 나오면 이어지고, 안 나오면 fixMissingPathFindings 가 닫는다.
     */
    String upsertPathFinding(long runId, AnalysisEngine.Change change) {
        String fingerprint = jdbc.queryForObject("""
                SELECT encode(sha256(convert_to(? || chr(10) || ? || chr(10) || p.full_name || chr(10) || r.pr_number, 'UTF8')), 'hex')
                FROM iac_runs r JOIN iac_repos p ON p.repo_id = r.repo_id WHERE r.run_id = ?
                """, String.class, change.ruleId(), change.fingerprint(), runId);
        var target = change.hops().getLast();
        jdbc.update("""
                INSERT INTO iac_findings (rule_id, source, enforcement, severity, environment, resource_address, params,
                                          fingerprint, last_run_id, first_seen_at, last_seen_at)
                SELECT ?, 'PATH', ?, ?, p.environment, ?, jsonb_build_object('tier', ?::int, 'pathFingerprint', ?::text),
                       ?, r.run_id, now(), now()
                FROM iac_runs r JOIN iac_repos p ON p.repo_id = r.repo_id WHERE r.run_id = ?
                ON CONFLICT (fingerprint) DO UPDATE
                SET enforcement = EXCLUDED.enforcement, severity = EXCLUDED.severity, last_run_id = EXCLUDED.last_run_id,
                    last_seen_at = EXCLUDED.last_seen_at,
                    status = CASE WHEN iac_findings.status = 'ACCEPTED' THEN 'ACCEPTED' ELSE 'OPEN' END,
                    version = iac_findings.version + 1
                """, change.ruleId(), change.enforcement(), change.severity(), target.name(), change.tier(),
                change.fingerprint(), fingerprint, runId);
        return fingerprint;
    }

    /** 같은 PR 의 이전 분석에서 열렸던 경로 발견 건 중 이번에 안 나온 것은 고쳐진 것으로 본다. */
    void fixMissingPathFindings(long runId, List<String> seen) {
        jdbc.update("""
                UPDATE iac_findings f SET status = 'FIXED', version = f.version + 1
                FROM iac_runs prev, iac_runs cur
                WHERE cur.run_id = ? AND f.source = 'PATH' AND f.status = 'OPEN' AND f.last_run_id = prev.run_id
                  AND prev.repo_id = cur.repo_id AND prev.pr_number = cur.pr_number AND prev.run_id <> cur.run_id
                  AND NOT (f.fingerprint = ANY (?))
                """, ps -> {
                    ps.setLong(1, runId);
                    ps.setArray(2, ps.getConnection().createArrayOf("varchar", seen.toArray()));
                });
    }

    /** 분석이 끝난 run 을 DONE 으로 두고, 분석에 쓴 plan 은 지운다 (SR-5). */
    boolean finishRun(long runId, String verdict, String highestSeverity, OffsetDateTime graphAsOf) {
        int updated = jdbc.update("""
                UPDATE iac_runs SET status = 'DONE', verdict = ?, highest_severity = ?, graph_as_of = ?, finished_at = now()
                WHERE run_id = ? AND status = 'ANALYZING'
                """, verdict, highestSeverity, graphAsOf, runId);
        jdbc.update("DELETE FROM iac_plan_payloads WHERE run_id = ?", runId);
        return updated == 1;
    }

    void jobStats(long jobId, String statsJson) {
        jdbc.update("UPDATE iac_jobs SET stats = ?::jsonb WHERE job_id = ?", statsJson, jobId);
    }

    void audit(long runId, String afterSafeJson) {
        jdbc.update("""
                INSERT INTO iac_audit_events (actor_kind, entity_type, entity_id, event_type, after_safe)
                VALUES ('WORKER', 'RUN', ?, 'RUN_ANALYZED', ?::jsonb)
                """, runId, afterSafeJson);
    }
}
