package com.logssey.iacworker.analysis;

import java.time.OffsetDateTime;
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
