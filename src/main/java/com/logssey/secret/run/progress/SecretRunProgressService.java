package com.logssey.secret.run.progress;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.access.SecretRole;
import com.logssey.secret.run.SecretRunService;
import com.logssey.secret.run.SecretRunStatusResponse;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SecretRunProgressService {
    private static final Set<String> TERMINAL = Set.of("SUCCEEDED", "PARTIAL", "FAILED", "SKIPPED", "CANCELLED");
    private final JdbcTemplate jdbc;
    private final SecretRunService runs;
    private final SecretAccessService access;

    public SecretRunProgressService(JdbcTemplate jdbc, SecretRunService runs, SecretAccessService access) {
        this.jdbc = jdbc;
        this.runs = runs;
        this.access = access;
    }

    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ)
    public SecretRunProgress progress(String login, long runId, long after, int size) {
        if (after < 0 || size < 1 || size > 200) throw new ApiException(ErrorCode.INVALID_INPUT);
        var run = runs.status(runId, login); // Includes current connection facts ACL on every page.
        var principal = access.requirePrincipal(login);
        var header = jdbc.queryForObject("""
                SELECT execution_trace_version,execution_recorded_at,execution_events_expired_at,
                 execution_event_count,execution_suppressed_count,execution_last_activity_at,
                 (SELECT j.finished_at FROM secret_jobs j WHERE j.job_id=r.job_id) AS job_finished_at,
                 clock_timestamp() AS captured_at,
                 EXISTS(SELECT 1 FROM secret_run_scopes s WHERE s.run_id=r.run_id AND s.object_count IS NOT NULL) AS objects_observed
                FROM secret_scan_runs r WHERE run_id=?
                """, (rs, n) -> new Header(rs.getObject("execution_trace_version", Integer.class),
                rs.getObject("execution_recorded_at", OffsetDateTime.class),
                rs.getObject("execution_events_expired_at", OffsetDateTime.class),
                rs.getLong("execution_event_count"), rs.getLong("execution_suppressed_count"),
                rs.getObject("execution_last_activity_at", OffsetDateTime.class),
                rs.getObject("job_finished_at", OffsetDateTime.class),
                rs.getObject("captured_at", OffsetDateTime.class), rs.getBoolean("objects_observed")), runId);
        if (after > header.count()) throw new ApiException(ErrorCode.INVALID_INPUT);
        var page = jdbc.query("""
                SELECT event_id,attempt_no,stage,operation_code,outcome,http_status,reason_code,
                 processed_count,total_count,duration_ms,observed_at
                FROM secret_run_execution_events WHERE run_id=? AND event_id>? ORDER BY event_id LIMIT ?
                """, (rs, n) -> new SecretRunProgress.Event(rs.getLong("event_id"), rs.getInt("attempt_no"),
                rs.getString("stage"), rs.getString("operation_code"), rs.getString("outcome"),
                rs.getObject("http_status", Integer.class), rs.getString("reason_code"),
                rs.getObject("processed_count", Long.class), rs.getObject("total_count", Long.class),
                rs.getObject("duration_ms", Long.class), rs.getObject("observed_at", OffsetDateTime.class)), runId, after, size + 1);
        boolean more = page.size() > size;
        var events = List.copyOf(more ? page.subList(0, size) : page);
        long next = events.isEmpty() ? after : events.getLast().id();
        String eventStatus = header.version() == null ? "NOT_RECORDED" : header.expired() != null ? "EXPIRED" : "AVAILABLE";
        boolean canView = access.hasConnectionRole(principal, run.connectionId(), SecretRole.SECURITY);
        boolean detectionObserved = Boolean.TRUE.equals(jdbc.queryForObject("""
                SELECT EXISTS(SELECT 1 FROM secret_run_execution_stage_facts WHERE run_id=? AND stage='DETECTION' AND started_at IS NOT NULL)
                 OR EXISTS(SELECT 1 FROM secret_tool_runs t JOIN secret_run_scopes s USING(run_scope_id)
                     WHERE s.run_id=? AND t.finished_at IS NOT NULL)
                """, Boolean.class, runId, runId));
        Long findingCount = canView && detectionObserved
                ? jdbc.queryForObject("SELECT count(*) FROM secret_findings WHERE run_id=?", Long.class, runId) : null;
        OffsetDateTime finishedAt = run.finishedAt() != null ? run.finishedAt()
                : TERMINAL.contains(run.status()) ? header.jobFinished() : null;
        var validation = validationSummary(run);
        return new SecretRunProgress(runId, run.connectionId(), run.provider(), run.status(), run.attemptNo(), run.maxAttempts(),
                run.requestedAt(), run.startedAt(), finishedAt, run.availableAt(), run.scopeCount(),
                run.completedScopeCount(),
                header.objectsObserved() ? run.collectedObjectCount() : null, findingCount,
                new SecretRunProgress.Capabilities(canView), header.captured(),
                header.latest() == null ? run.requestedAt() : header.latest(), 2500, eventStatus,
                "AVAILABLE".equals(eventStatus) && header.suppressed() == 0,
                header.suppressed() > 0, header.suppressed(), header.recorded(), header.expired(),
                stages(run, header.version() != null, validation), events, next, more, validation);
    }

    private SecretRunProgress.ValidationSummary validationSummary(SecretRunStatusResponse run) {
        boolean reuseRecorded = Boolean.TRUE.equals(jdbc.queryForObject(
                "SELECT validation_reuse_version=1 AND validation_reuse_attempt=? FROM secret_scan_runs WHERE run_id=?",
                Boolean.class, run.attemptNo(), run.runId()));
        var counts = jdbc.queryForObject("""
                SELECT count(*) FILTER(WHERE request_sent_at IS NOT NULL) AS sent,
                 count(*) FILTER(WHERE request_sent_at IS NOT NULL AND attempt_state='COMPLETED') AS completed,
                 count(*) FILTER(WHERE result='UNCHECKED') AS unchecked,
                 count(*) FILTER(WHERE result='UNCHECKED' AND reason_code IN('INCOMPLETE_PAIR','MISSING_SESSION_TOKEN','INCOMPLETE_CREDENTIAL')) AS incomplete,
                 count(*) FILTER(WHERE result='UNKNOWN' OR attempt_state='ABANDONED') AS unknown
                FROM secret_validation_attempts WHERE run_id=? AND attempt_no=? AND evidence_version=1
                """, (rs, n) -> new long[]{rs.getLong("sent"), rs.getLong("completed"),
                rs.getLong("unchecked"), rs.getLong("incomplete"), rs.getLong("unknown")},
                run.runId(), run.attemptNo());
        var reused = jdbc.query("""
                SELECT k.issuer,a.result,a.reason_code,a.provider_checked_at,a.run_id,count(*) AS count
                FROM secret_validation_reuses reuse
                JOIN secret_validation_attempts a ON a.attempt_id=reuse.source_attempt_id
                JOIN secret_credential_sets k ON k.credential_set_id=reuse.credential_set_id
                WHERE reuse.run_id=? AND reuse.attempt_no=?
                GROUP BY k.issuer,a.result,a.reason_code,a.provider_checked_at,a.run_id
                ORDER BY a.provider_checked_at,k.issuer,a.run_id LIMIT 51
                """, (rs, n) -> new SecretRunProgress.ReusedResult(rs.getString("issuer"),
                rs.getString("result"), rs.getString("reason_code"),
                rs.getObject("provider_checked_at", OffsetDateTime.class), rs.getLong("run_id"),
                rs.getLong("count")), run.runId(), run.attemptNo());
        Long reusedCount = reuseRecorded ? jdbc.queryForObject(
                "SELECT count(*) FROM secret_validation_reuses WHERE run_id=? AND attempt_no=?",
                Long.class, run.runId(), run.attemptNo()) : null;
        boolean truncated = reused.size() > 50;
        // Use this attempt's persisted decisions, not today's settings or the last event alone.
        // Reason codes pass through the execution allowlist; no source values leave this API.
        var uncheckedReasons = jdbc.query("""
                SELECT COALESCE(secret_execution_safe_reason(reason_code),'UNRECORDED_REASON') AS reason,
                 count(*) AS count
                FROM secret_validation_attempts
                WHERE run_id=? AND attempt_no=? AND evidence_version=1 AND result='UNCHECKED'
                GROUP BY 1 ORDER BY count(*) DESC,1
                """, (rs, n) -> new SecretRunProgress.UncheckedReason(rs.getString("reason"), rs.getLong("count")),
                run.runId(), run.attemptNo());
        return new SecretRunProgress.ValidationSummary(reuseRecorded, counts[0], counts[1],
                reusedCount, counts[2], counts[3], counts[4],
                List.copyOf(truncated ? reused.subList(0, 50) : reused), truncated, List.copyOf(uncheckedReasons));
    }

    private List<SecretRunProgress.Stage> stages(SecretRunStatusResponse run, boolean recorded,
                                              SecretRunProgress.ValidationSummary validation) {
        var result = new ArrayList<SecretRunProgress.Stage>();
        String cancellationReason = "CANCELLED".equals(run.status()) ? jdbc.queryForObject("""
                SELECT COALESCE(secret_execution_safe_reason(j.last_error_code),'CANCELLED')
                FROM secret_jobs j JOIN secret_scan_runs r USING(job_id) WHERE r.run_id=?
                """, String.class, run.runId()) : null;
        for (String key : List.of("QUEUE", "COLLECTION", "DETECTION", "VALIDATION", "RESULT")) {
            var times = jdbc.queryForObject("""
                    SELECT min(started_at) AS started,max(finished_at) AS finished,
                     count(*) FILTER(WHERE started_at IS NOT NULL) AS begins
                    FROM secret_run_execution_stage_facts WHERE run_id=? AND attempt_no=? AND stage=?
                    """, (rs, n) -> new Times(rs.getObject("started", OffsetDateTime.class),
                    rs.getObject("finished", OffsetDateTime.class), rs.getLong("begins")), run.runId(), run.attemptNo(), key);
            String ledger = switch (key) {
                case "QUEUE" -> "PENDING".equals(run.status()) ? "PENDING"
                        : run.attemptNo() > 0 ? "SUCCEEDED" : TERMINAL.contains(run.status()) ? run.status() : "PENDING";
                case "COLLECTION" -> run.collectionStatus();
                case "DETECTION" -> run.detectionStatus();
                case "VALIDATION" -> run.validationStatus();
                default -> run.status();
            };
            // A processor marks all three stages RUNNING eagerly. Only actual observations start them.
            String state = ledger;
            boolean retryWaiting = "PENDING".equals(run.status()) && run.attemptNo() > 0;
            boolean unobservedSuccess = recorded && !"QUEUE".equals(key) && !"RESULT".equals(key)
                    && "SUCCEEDED".equals(ledger) && times.begins() == 0;
            if (recorded && !TERMINAL.contains(run.status()) && !"QUEUE".equals(key)) {
                state = !retryWaiting && times.begins() > 0 ? "RUNNING" : "PENDING";
            } else if (unobservedSuccess) {
                state = "UNKNOWN";
            }
            String reason = jdbc.query("""
                    SELECT reason_code FROM secret_run_execution_events WHERE run_id=? AND attempt_no=?
                     AND stage=? AND reason_code IS NOT NULL ORDER BY event_id DESC LIMIT 1
                    """, rs -> rs.next() ? rs.getString(1) : null, run.runId(), run.attemptNo(), key);
            if (reason == null && "SKIPPED".equals(state)) {
                reason = jdbc.queryForObject("""
                        SELECT secret_execution_safe_reason(CASE WHEN bool_and(right(snapshot_content_type,9)='_METADATA')
                         THEN 'NOT_APPLICABLE_METADATA' WHEN ?='DETECTION' AND COALESCE(sum(object_count),0)=0
                         THEN 'NO_OBJECTS' ELSE min(CASE WHEN ?='VALIDATION' THEN validation_reason_code ELSE detection_reason_code END) END)
                        FROM secret_run_scopes WHERE run_id=?
                        """, String.class, key, key, run.runId());
            }
            if (unobservedSuccess) reason = "STAGE_NOT_OBSERVED";
            if ("VALIDATION".equals(key) && "SKIPPED".equals(state) && !validation.uncheckedReasons().isEmpty()) {
                // A final scope summary can say NO_CANDIDATES even when another scope was blocked.
                // Preserve all reasons in the summary instead of choosing a single scope arbitrarily.
                reason = validation.uncheckedReasons().size() == 1
                        ? validation.uncheckedReasons().getFirst().reasonCode() : "MULTIPLE_VALIDATION_REASONS";
            }
            if (cancellationReason != null) {
                if (Set.of("PENDING", "RUNNING").contains(ledger)) state = "CANCELLED";
                if ("CANCELLED".equals(state)) reason = cancellationReason;
            }
            Long processed = null, total = null;
            String unit = null;
            if ("COLLECTION".equals(key)) {
                unit = "SCOPE";
                total = run.scopeCount();
                if (!retryWaiting && times.begins() > 0) {
                    processed = jdbc.queryForObject("""
                            SELECT COALESCE(sum(completed_scopes),0) FROM secret_run_execution_stage_facts
                            WHERE run_id=? AND attempt_no=? AND stage='COLLECTION'
                            """, Long.class, run.runId(), run.attemptNo());
                } else if (!recorded) {
                    processed = run.completedScopeCount();
                }
            } else if ("DETECTION".equals(key) && !retryWaiting && times.begins() > 0) {
                unit = "OBJECT";
                processed = jdbc.queryForObject("""
                        SELECT COALESCE(sum(completed_objects),0) FROM secret_run_execution_stage_facts WHERE run_id=? AND attempt_no=? AND stage='DETECTION'
                        """, Long.class, run.runId(), run.attemptNo());
            } else if ("VALIDATION".equals(key) && !retryWaiting) {
                unit = "ATTEMPT";
                var counts = jdbc.queryForObject("""
                        SELECT count(*) FILTER(WHERE request_sent_at IS NOT NULL) AS total,
                         count(*) FILTER(WHERE attempt_state='COMPLETED' AND request_sent_at IS NOT NULL) AS completed
                        FROM secret_validation_attempts WHERE run_id=? AND attempt_no=? AND evidence_version=1
                        """, (rs, n) -> new long[]{rs.getLong("total"), rs.getLong("completed")}, run.runId(), run.attemptNo());
                if (counts[0] > 0) { processed = counts[1]; total = TERMINAL.contains(run.status()) ? counts[0] : null; }
                else if ("SKIPPED".equals(state)) { processed = 0L; total = 0L; }
            }
            result.add(new SecretRunProgress.Stage(key, state,
                    retryWaiting && !"QUEUE".equals(key) ? null : "QUEUE".equals(key) && times.started() == null ? run.requestedAt() : times.started(),
                    retryWaiting && !"QUEUE".equals(key) ? null : times.finished(), reason, processed, total, unit));
        }
        return List.copyOf(result);
    }

    private record Header(Integer version, OffsetDateTime recorded, OffsetDateTime expired, long count,
                          long suppressed, OffsetDateTime latest, OffsetDateTime jobFinished, OffsetDateTime captured, boolean objectsObserved) {}
    private record Times(OffsetDateTime started, OffsetDateTime finished, long begins) {}
}
