package com.logssey.secretworker;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
class SecretJobRepository {

    private final JdbcTemplate jdbc;

    SecretJobRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    OffsetDateTime databaseNow() {
        return jdbc.queryForObject("SELECT clock_timestamp()", OffsetDateTime.class);
    }

    List<JobRow> lockAvailable(OffsetDateTime now, int limit, String provider) {
        return jdbc.query("""
                SELECT j.job_id, r.run_id, j.connection_id, j.attempt_no, j.max_attempts,
                       j.status, j.lease_owner, j.lease_until
                FROM secret_jobs j
                JOIN secret_connections c ON c.connection_id = j.connection_id
                JOIN secret_scan_runs r ON r.job_id = j.job_id
                WHERE j.status = 'PENDING' AND j.available_at <= ? AND c.status = 'ACTIVE'
                  AND c.provider = COALESCE(?, c.provider)
                ORDER BY j.available_at, j.job_id
                LIMIT ? FOR UPDATE OF j SKIP LOCKED
                """, (rs, row) -> jobRow(rs), now, provider, limit);
    }

    List<JobRow> lockExpired(OffsetDateTime now, int limit) {
        return jdbc.query("""
                SELECT j.job_id, r.run_id, j.connection_id, j.attempt_no, j.max_attempts,
                       j.status, j.lease_owner, j.lease_until
                FROM secret_jobs j
                JOIN secret_scan_runs r ON r.job_id = j.job_id
                WHERE j.status = 'LEASED' AND j.lease_until <= ?
                ORDER BY j.lease_until, j.job_id
                LIMIT ? FOR UPDATE OF j SKIP LOCKED
                """, (rs, row) -> jobRow(rs), now, limit);
    }

    Optional<JobRow> lockJob(long jobId) {
        return jdbc.query("""
                SELECT j.job_id, r.run_id, j.connection_id, j.attempt_no, j.max_attempts,
                       j.status, j.lease_owner, j.lease_until
                FROM secret_jobs j
                JOIN secret_scan_runs r ON r.job_id = j.job_id
                WHERE j.job_id = ? FOR UPDATE OF j
                """, rs -> rs.next() ? Optional.of(jobRow(rs)) : Optional.empty(), jobId);
    }

    ClaimedSecretJob claim(JobRow row, OffsetDateTime now, OffsetDateTime leaseUntil, String token) {
        jdbc.update("""
                UPDATE secret_jobs
                SET status = 'LEASED', lease_owner = ?, lease_until = ?, attempt_no = attempt_no + 1,
                    last_error_code = NULL
                WHERE job_id = ?
                """, token, leaseUntil, row.jobId());
        jdbc.update("""
                UPDATE secret_scan_runs
                SET started_at = COALESCE(started_at, ?), result_status = 'RUNNING', failure_code = NULL
                WHERE run_id = ?
                """, now, row.runId());
        return new ClaimedSecretJob(row.jobId(), row.runId(), row.connectionId(),
                row.attemptNo() + 1, token, leaseUntil);
    }

    boolean renew(long jobId, String token, Duration leaseDuration) {
        return jdbc.update("""
                UPDATE secret_jobs SET lease_until = clock_timestamp() + (? * INTERVAL '1 millisecond')
                WHERE job_id = ? AND status = 'LEASED' AND lease_owner = ?
                  AND lease_until > clock_timestamp()
                """, leaseDuration.toMillis(), jobId, token) == 1;
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
        updateLastCollectionSuccess(row);
    }

    void retry(JobRow row, OffsetDateTime now, OffsetDateTime availableAt, String code) {
        jdbc.update("""
                UPDATE secret_jobs
                SET status = 'PENDING', available_at = ?, lease_owner = NULL, lease_until = NULL,
                    last_error_code = ?
                WHERE job_id = ?
                """, availableAt, code, row.jobId());
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
                    collection_status = 'PENDING', object_count = NULL, failure_code = NULL,
                    started_at = NULL, finished_at = NULL
                WHERE run_id = ? AND collection_status IN ('RUNNING', 'PARTIAL', 'FAILED')
                """, row.runId());
        // A completed collection remains evidence of success even when a later stage needs a retry.
        updateLastCollectionSuccess(row);
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
        updateLastCollectionSuccess(row);
    }

    private void updateLastCollectionSuccess(JobRow row) {
        jdbc.update("""
                UPDATE secret_connections c SET last_collection_success_at = completed.completed_at
                FROM (
                    SELECT r.connection_id, MAX(s.finished_at) AS completed_at
                    FROM secret_scan_runs r
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
                rs.getString("lease_owner"), rs.getObject("lease_until", OffsetDateTime.class));
    }

    record JobRow(long jobId, long runId, long connectionId, int attemptNo, int maxAttempts,
                  String status, String leaseOwner, OffsetDateTime leaseUntil) {
        boolean isLiveLease(String token, OffsetDateTime now) {
            return "LEASED".equals(status) && leaseOwner != null && leaseOwner.equals(token)
                    && leaseUntil != null && leaseUntil.isAfter(now);
        }
    }

    record RunState(String collection, String detection, String validation, String result) {
    }

    record ScopeState(long total, long terminal, long incomplete, long usable,
                      long uncompleted, long objectTotal) {
    }
}
