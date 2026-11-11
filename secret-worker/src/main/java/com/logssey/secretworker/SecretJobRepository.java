package com.logssey.secretworker;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

@Repository
class SecretJobRepository {

    private final JdbcTemplate jdbc;

    SecretJobRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    com.logssey.secret.run.progress.core.ScanExecutionObserver observer(ClaimedSecretJob job, Long scopeId) {
        var events = new com.logssey.secret.run.progress.core.ScanExecutionEvents(jdbc);
        return (stage, operation, outcome, http, reason, processed, total, duration) -> {
            if (!events.append(job.jobId(), job.leaseToken(), job.leaseGeneration(), scopeId,
                    stage, operation, outcome, http, reason, processed, total, duration)) {
                throw new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
            }
        };
    }

    OffsetDateTime databaseNow() {
        return jdbc.queryForObject("SELECT clock_timestamp()", OffsetDateTime.class);
    }

    List<JobRow> lockAvailable(OffsetDateTime now, int limit, String provider) {
        return jdbc.query(
                """
SELECT j.job_id, r.run_id, j.connection_id, j.attempt_no, j.max_attempts,
       j.status, j.lease_owner, j.lease_until,j.lease_token::text AS fence_token,j.lease_generation
FROM secret_jobs j
JOIN secret_connections c ON c.connection_id = j.connection_id
JOIN secret_scan_runs r ON r.job_id = j.job_id
WHERE j.status = 'PENDING' AND j.available_at <= ? AND c.status = 'ACTIVE'
  AND c.provider = COALESCE(?, c.provider)
  AND (c.provider<>'NOTION' OR NOT EXISTS(SELECT 1 FROM secret_connections cooldown
    WHERE cooldown.provider='NOTION' AND cooldown.auth_ref=c.auth_ref
      AND cooldown.source_retry_at>clock_timestamp()))
ORDER BY j.available_at, j.job_id
LIMIT ? FOR UPDATE OF j SKIP LOCKED
""", (rs, row) -> jobRow(rs), now, provider, limit);
    }

    List<JobRow> lockExpired(OffsetDateTime now, int limit) {
        return jdbc.query(
                """
SELECT j.job_id, r.run_id, j.connection_id, j.attempt_no, j.max_attempts,
       j.status, j.lease_owner, j.lease_until,j.lease_token::text AS fence_token,j.lease_generation
FROM secret_jobs j
JOIN secret_scan_runs r ON r.job_id = j.job_id
WHERE j.status = 'LEASED' AND j.lease_until <= ?
ORDER BY j.lease_until, j.job_id
LIMIT ? FOR UPDATE OF j SKIP LOCKED
""", (rs, row) -> jobRow(rs), now, limit);
    }

    Optional<JobRow> lockJob(long jobId) {
        return jdbc.query(
                """
SELECT j.job_id, r.run_id, j.connection_id, j.attempt_no, j.max_attempts,
       j.status, j.lease_owner, j.lease_until,j.lease_token::text AS fence_token,j.lease_generation
FROM secret_jobs j
JOIN secret_scan_runs r ON r.job_id = j.job_id
WHERE j.job_id = ? FOR UPDATE OF j
""", rs -> rs.next() ? Optional.of(jobRow(rs)) : Optional.empty(), jobId);
    }

    ClaimedSecretJob claim(JobRow row, OffsetDateTime now, OffsetDateTime leaseUntil, String token) {
        jdbc.update(
                """
UPDATE secret_jobs
SET status = 'LEASED', lease_owner = ?, lease_until = ?, attempt_no = attempt_no + 1,
    lease_token = ?::uuid, lease_generation = lease_generation + 1,
    last_error_code = NULL
WHERE job_id = ?
""", token, leaseUntil,
                token, row.jobId());
        jdbc.update("""
                UPDATE secret_scan_runs
                SET started_at = COALESCE(started_at, ?), result_status = 'RUNNING', failure_code = NULL
                WHERE run_id = ?
                """, now, row.runId());
        return new ClaimedSecretJob(row.jobId(), row.runId(), row.connectionId(),
                row.attemptNo() + 1, token, leaseUntil,
                jdbc.queryForObject(
                        "SELECT lease_generation FROM secret_jobs WHERE job_id=?",
                        Long.class,
                        row.jobId()));
    }

    boolean renew(long jobId, String token, Duration leaseDuration) {
        return jdbc.update(
                        """
UPDATE secret_jobs SET lease_until = clock_timestamp() + (? * INTERVAL '1 millisecond')
WHERE job_id = ? AND status = 'LEASED' AND lease_owner = ?
  AND lease_until > clock_timestamp() AND lease_token::text = ?
""", leaseDuration.toMillis(), jobId,
                        token, token) == 1;
    }

    RunState runState(long runId) {
        return jdbc.queryForObject("""
                SELECT collection_status, detection_status, validation_status, result_status
                FROM secret_scan_runs WHERE run_id = ?
                """, (rs, row) -> new RunState(rs.getString("collection_status"),
                rs.getString("detection_status"), rs.getString("validation_status"),
                rs.getString("result_status")), runId);
    }

    ScopeState scopeState(long runId) {
        return jdbc.queryForObject("""
                SELECT COUNT(*) AS total,
                       COUNT(*) FILTER (WHERE collection_status IN ('SUCCEEDED', 'PARTIAL', 'FAILED', 'SKIPPED')) AS terminal,
                       COUNT(*) FILTER (WHERE collection_status IN ('PARTIAL', 'FAILED', 'SKIPPED')) AS incomplete,
                       COUNT(*) FILTER (WHERE rs.collection_status = 'SUCCEEDED'
                                            OR (rs.collection_status = 'PARTIAL'
                                                AND (rs.object_count > 0
                                                     OR (RIGHT(s.content_type, 9) = '_METADATA'
                                                         AND rs.object_count IS NOT NULL)))) AS usable,
                       COUNT(*) FILTER (WHERE collection_status = 'SUCCEEDED'
                                            AND (object_count IS NULL OR finished_at IS NULL)) AS uncompleted,
                       COALESCE(SUM(CASE WHEN RIGHT(s.content_type, 9) = '_METADATA'
                           THEN 0 ELSE rs.object_count END), 0) AS detector_object_total
                FROM secret_run_scopes rs
                JOIN secret_connection_scopes s ON s.scope_id = rs.scope_id
                WHERE rs.run_id = ?
                """, (rs, row) -> new ScopeState(rs.getLong("total"), rs.getLong("terminal"),
                rs.getLong("incomplete"), rs.getLong("usable"), rs.getLong("uncompleted"),
                rs.getLong("detector_object_total")), runId);
    }

    void recordScopeEvidence(long runScopeId, boolean validationFailed) {
        jdbc.queryForObject("SELECT secret_record_scope_evidence(?, ?)", Object.class, runScopeId, validationFailed);
    }

    void startResult(JobRow row) {
        jdbc.queryForObject("""
                SELECT secret_record_execution_event(?,?::uuid,?,NULL,'RESULT','STAGE_SUMMARY','STARTED',
                 NULL,NULL,NULL,NULL,NULL,?)
                """, Boolean.class, row.jobId(), row.fenceToken(), row.leaseGeneration(),
                "result-start:" + row.attemptNo());
    }

    void finish(JobRow row, OffsetDateTime now, String resultStatus) {
        jdbc.update("""
                UPDATE secret_jobs SET status = 'SUCCEEDED', lease_owner = NULL, lease_until = NULL,
                                       last_error_code = NULL, finished_at = ?
                WHERE job_id = ?
                """, now, row.jobId());
        jdbc.update("""
                UPDATE secret_scan_runs SET result_status = ?,
                    failure_code = CASE WHEN ? = 'SUCCEEDED' THEN NULL ELSE failure_code END,
                    finished_at = ?
                WHERE run_id = ?
                """, resultStatus, resultStatus, now, row.runId());
        new SecretFullScanPresence(jdbc).reconcile(row.runId(),now);
        if(Boolean.TRUE.equals(jdbc.queryForObject(
                        "SELECT to_regprocedure('secret_apply_storage_policy_defaults(bigint)') IS"
                            + " NOT NULL",Boolean.class))) {
            jdbc.queryForObject("SELECT secret_apply_storage_policy_defaults(?)",Object.class,row.runId());
        }
        new com.logssey.secretworker.evidence.TrustedFixtureComparator(jdbc).compareRun(row.runId(),now);
        jdbc.queryForObject("SELECT secret_reconcile_test_alerts(?)",Long.class,row.runId());
        finishRevalidation(row, now);
        updateLastCollectionSuccess(row);
    }

    boolean isCredentialValidation(long jobId) {
        return Boolean.TRUE.equals(
                jdbc.queryForObject(
                        "SELECT purpose='CREDENTIAL_VALIDITY' FROM secret_jobs WHERE job_id=?",
                        Boolean.class,
                        jobId));
    }

    void finishValidation(JobRow row, OffsetDateTime now, String outcome) {
        jdbc.update(
                "UPDATE secret_jobs SET"
                    + " status='SUCCEEDED',lease_owner=NULL,lease_until=NULL,lease_token=NULL,finished_at=?"
                    + " WHERE job_id=?",
                now,
                row.jobId());
        jdbc.update(
                "UPDATE secret_scan_runs SET result_status=?,finished_at=? WHERE run_id=?",
                outcome,
                now,
                row.runId());
    }

    boolean retry(JobRow row, OffsetDateTime now, OffsetDateTime availableAt, String code) {
        var retryAt = jdbc.queryForObject(
                "SELECT GREATEST(?::timestamptz,COALESCE((SELECT max(next_due_at)"
                        + " FROM secret_validation_attempts WHERE run_id=?),?::timestamptz),"
                        + "COALESCE((SELECT source_retry_at FROM secret_connections WHERE connection_id=?),?::timestamptz))",
                OffsetDateTime.class, availableAt, row.runId(), availableAt, row.connectionId(), availableAt);
        // Leave the registered maximum request duration inside the validation run's budget.
        if (("VALIDATOR_TEMPORARY".equals(code) || isCredentialValidation(row.jobId()))
                && Boolean.TRUE.equals(jdbc.queryForObject(
                "SELECT ?::timestamptz+interval '8 seconds'>=started_at+interval '30 minutes'"
                        + " FROM secret_scan_runs WHERE run_id=?",
                Boolean.class, retryAt, row.runId()))) return false;
        jdbc.update(
                """
UPDATE secret_jobs
SET status = 'PENDING', available_at = ?, lease_owner = NULL, lease_until = NULL,
    last_error_code = ?
WHERE job_id = ?
""",
                retryAt, code, row.jobId());
        jdbc.update("""
                UPDATE secret_scan_runs SET
                    collection_status = CASE WHEN collection_status IN ('RUNNING', 'PARTIAL', 'FAILED')
                                             THEN 'PENDING' ELSE collection_status END,
                    detection_status = CASE WHEN detection_status IN ('RUNNING', 'PARTIAL', 'FAILED')
                                            THEN 'PENDING' ELSE detection_status END,
                    validation_status = CASE WHEN validation_status IN ('RUNNING', 'PARTIAL', 'FAILED')
                                             THEN 'PENDING' ELSE validation_status END,
                    result_status = 'PENDING', failure_code = ?, finished_at = NULL
                WHERE run_id = ?
                """, code, row.runId());
        jdbc.update("""
                UPDATE secret_run_scopes SET
                    collection_status = 'PENDING', object_count = NULL, failure_code = NULL,excluded_object_count=0,
                    started_at = NULL, finished_at = NULL
                WHERE run_id = ? AND collection_status IN ('RUNNING', 'PARTIAL', 'FAILED')
                """, row.runId());
        new SecretFullScanPresence(jdbc).reconcile(row.runId(),now);
        // A completed collection remains evidence of success even when a later stage needs a retry.
        updateLastCollectionSuccess(row);
        return true;
    }

    void failPermanently(JobRow row, OffsetDateTime now, String code) {
        jdbc.update("""
                UPDATE secret_jobs
                SET status = 'FAILED', lease_owner = NULL, lease_until = NULL,
                    last_error_code = ?, finished_at = ?
                WHERE job_id = ?
                """, code, now, row.jobId());
        jdbc.update("""
                UPDATE secret_scan_runs SET
                    collection_status = CASE WHEN collection_status = 'RUNNING' THEN 'FAILED'
                                             WHEN collection_status = 'PENDING' THEN 'SKIPPED' ELSE collection_status END,
                    detection_status = CASE WHEN detection_status = 'RUNNING' THEN 'FAILED'
                                            WHEN detection_status = 'PENDING' THEN 'SKIPPED' ELSE detection_status END,
                    validation_status = CASE WHEN validation_status = 'RUNNING' THEN 'FAILED'
                                             WHEN validation_status = 'PENDING' THEN 'SKIPPED' ELSE validation_status END,
                    result_status = 'FAILED', failure_code = ?, finished_at = ?
                WHERE run_id = ?
                """, code, now, row.runId());
        jdbc.update("""
                UPDATE secret_run_scopes SET
                    collection_status = CASE WHEN collection_status = 'RUNNING' THEN 'FAILED'
                                             WHEN collection_status = 'PENDING' THEN 'SKIPPED' ELSE collection_status END,
                    failure_code = CASE WHEN collection_status = 'RUNNING' THEN ? ELSE failure_code END,
                    finished_at = CASE WHEN collection_status IN ('RUNNING', 'PENDING') THEN ? ELSE finished_at END
                WHERE run_id = ?
                """, code, now, row.runId());
        jdbc.update("""
                UPDATE secret_case_revalidations
                SET status = 'UNKNOWN', failure_code = ?, finished_at = ?
                WHERE run_id = ? AND status = 'PENDING'
                """, code, now, row.runId());
        new SecretFullScanPresence(jdbc).reconcile(row.runId(),now);
        updateLastCollectionSuccess(row);
    }

    private void finishRevalidation(JobRow row, OffsetDateTime now) {
        jdbc.update("""
                WITH outcome AS (
                    SELECT v.revalidation_id,
                           CASE WHEN r.collection_status = 'SUCCEEDED'
                                  AND r.detection_status IN ('SUCCEEDED', 'SKIPPED')
                                  AND rs.collection_status = 'SUCCEEDED'
                                  AND rs.detection_stage_status IN ('SUCCEEDED','SKIPPED')
                                  AND rs.scope_revision = v.scope_revision AND scope.revision = v.scope_revision AND scope.response_origin_version=v.scope_origin_version
                                  AND co.action_cycle = v.action_cycle AND co.version = v.occurrence_version
                                  AND co.last_material_action_at = v.last_material_action_at
                                  AND co.actions_completed_at = v.actions_completed_at
                                  AND co.response_status = 'REVALIDATION_PENDING'
                                  AND c.is_current AND c.disposition='IN_SCOPE'
                                  AND c.case_origin=scope.response_origin AND conn.status='ACTIVE' AND scope.enabled
                                  AND k.fingerprint_key_version = v.baseline_fingerprint_version AND k.fingerprint = v.baseline_identity
                                  AND v.requested_at >= v.actions_completed_at AND v.requested_at > v.last_material_action_at
                                  AND rs.started_at >= v.requested_at AND rs.finished_at >= v.actions_completed_at
                                  AND tr.status = 'SUCCEEDED'
                                  AND tr.config_hash = v.baseline_config_hash
                                  AND tr.engine_version = v.baseline_engine_version
                                  AND v.runtime_fingerprint_version = v.baseline_fingerprint_version
                                  AND r.scope_version = conn.scope_version
                                  AND v.requested_at > a.performed_at
                                THEN CASE WHEN EXISTS (
                                    SELECT 1 FROM secret_findings f
                                    JOIN secret_occurrences found
                                      ON found.occurrence_id = f.occurrence_id
                                    JOIN secret_response_cases c ON c.case_id = v.case_id
                                    WHERE f.run_id = v.run_id
                                      AND found.scope_id = v.scope_id AND found.occurrence_id=v.occurrence_id
                                      AND found.credential_set_id = c.credential_set_id
                                ) THEN 'PRESENT'
                                  WHEN scope.content_type='NOTION_PAGE_CONTENT' THEN 'UNKNOWN'
                                  ELSE 'MISSING' END
                                ELSE 'UNKNOWN' END AS result
                    FROM secret_case_revalidations v
                    JOIN secret_scan_runs r ON r.run_id = v.run_id
                    JOIN secret_connections conn ON conn.connection_id = v.connection_id
                    JOIN secret_connection_scopes scope ON scope.scope_id = v.scope_id
                    JOIN secret_case_occurrences co ON co.case_id=v.case_id AND co.occurrence_id=v.occurrence_id
                    JOIN secret_response_cases c ON c.case_id=v.case_id
                    JOIN secret_credential_sets k ON k.credential_set_id=c.credential_set_id
                    JOIN secret_action_records a ON a.action_id = v.action_id
                    LEFT JOIN secret_run_scopes rs
                      ON rs.run_id = v.run_id AND rs.scope_id = v.scope_id
                    LEFT JOIN secret_tool_runs tr
                      ON tr.run_scope_id = rs.run_scope_id AND tr.engine = 'GITLEAKS'
                    WHERE v.run_id = ? AND v.status = 'PENDING'
                )
                UPDATE secret_case_revalidations v
                SET status = outcome.result,
                    failure_code = CASE WHEN outcome.result = 'UNKNOWN'
                        THEN 'REVALIDATION_INCOMPLETE' ELSE NULL END,
                    finished_at = ?
                FROM outcome WHERE v.revalidation_id = outcome.revalidation_id
                """, row.runId(), now);
        jdbc.update("""
                UPDATE secret_occurrences o
                SET presence_status = 'MISSING', last_complete_coverage_at = ?
                FROM secret_case_revalidations v
                WHERE v.run_id = ? AND v.status = 'MISSING'
                  AND o.occurrence_id = v.occurrence_id
                  AND (o.last_seen_run_id IS NULL OR o.last_seen_run_id <> v.run_id)
                """, now, row.runId());
    }

    private void updateLastCollectionSuccess(JobRow row) {
        jdbc.update("""
                UPDATE secret_connections c SET last_collection_success_at = completed.completed_at
                FROM (
                    SELECT r.connection_id, MAX(s.finished_at) AS completed_at
                    FROM secret_scan_runs r
                    JOIN secret_jobs j ON j.job_id=r.job_id AND j.kind='FULL_SCAN'
                    JOIN secret_run_scopes s ON s.run_id = r.run_id
                    WHERE r.run_id = ? AND r.collection_status = 'SUCCEEDED'
                    GROUP BY r.connection_id
                    HAVING COUNT(*) > 0
                       AND COUNT(*) FILTER (WHERE s.collection_status <> 'SUCCEEDED'
                                               OR s.object_count IS NULL OR s.finished_at IS NULL) = 0
                ) completed
                WHERE c.connection_id = ? AND c.connection_id = completed.connection_id
                  AND (c.last_collection_success_at IS NULL
                       OR c.last_collection_success_at < completed.completed_at)
                """, row.runId(), row.connectionId());
    }

    private JobRow jobRow(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new JobRow(rs.getLong("job_id"), rs.getLong("run_id"), rs.getLong("connection_id"),
                rs.getInt("attempt_no"), rs.getInt("max_attempts"), rs.getString("status"),
                rs.getString("lease_owner"), rs.getObject("lease_until", OffsetDateTime.class),
                rs.getString("fence_token"),
                rs.getLong("lease_generation"));
    }

    record JobRow(long jobId, long runId, long connectionId, int attemptNo, int maxAttempts,
                  String status, String leaseOwner, OffsetDateTime leaseUntil,
            String fenceToken,
            long leaseGeneration) {
        JobRow(
                long jobId,
                long runId,
                long connectionId,
                int attemptNo,
                int maxAttempts,
                String status,
                String owner,
                OffsetDateTime until) {
            this(
                    jobId,
                    runId,
                    connectionId,
                    attemptNo,
                    maxAttempts,
                    status,
                    owner,
                    until,
                    owner,
                    Math.max(1, attemptNo));
        }
        boolean isLiveLease(String token, OffsetDateTime now) {
            return "LEASED".equals(status) && leaseOwner != null && leaseOwner.equals(token)
                    && token.equals(fenceToken)
                    && leaseGeneration > 0
                    && leaseUntil != null && leaseUntil.isAfter(now);
        }
    }

    record RunState(String collection, String detection, String validation, String result) {
    }

    record ScopeState(long total, long terminal, long incomplete, long usable,
                      long uncompleted, long objectTotal) {
    }
}
