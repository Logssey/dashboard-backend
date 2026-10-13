package com.logssey.secret.run;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.List;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
class SecretRunRepository {

    private final JdbcTemplate jdbc;

    SecretRunRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    Optional<Actor> actor(String loginId) {
        return jdbc.query("SELECT user_id, role FROM dashboard_users WHERE login_id = ?",
                (rs, row) -> new Actor(rs.getLong("user_id"), rs.getString("role")), loginId)
                .stream().findFirst();
    }

    void lockIdempotencyKey(long lockKey) {
        // The lock orders simultaneous requests with the same key, even across different connections.
        // A hash collision only serializes unrelated requests; the full digest is still compared below.
        jdbc.queryForObject("SELECT pg_advisory_xact_lock(?)", Object.class, lockKey);
    }

    Optional<JobRun> byIdempotencyKey(String key) {
        return jdbc.query("""
                SELECT j.connection_id, j.requested_by_user_id, j.idempotency_key, j.status AS job_status,
                       r.run_id, r.result_status
                FROM secret_jobs j JOIN secret_scan_runs r ON r.job_id = j.job_id
                WHERE j.idempotency_key = ?
                """, (rs, row) -> jobRun(rs), key).stream().findFirst();
    }

    Optional<Connection> lockConnection(long connectionId) {
        return jdbc.query("""
                SELECT connection_id, provider, status, scope_version FROM secret_connections
                WHERE connection_id = ? FOR UPDATE
                """, (rs, row) -> new Connection(rs.getLong("connection_id"),
                rs.getString("provider"), rs.getString("status"),
                rs.getLong("scope_version")), connectionId)
                .stream().findFirst();
    }

    Optional<JobRun> activeRun(long connectionId) {
        return jdbc.query("""
                SELECT j.connection_id, j.requested_by_user_id, j.idempotency_key, j.status AS job_status,
                       r.run_id, r.result_status
                FROM secret_jobs j JOIN secret_scan_runs r ON r.job_id = j.job_id
                WHERE j.connection_id = ? AND j.kind = 'FULL_SCAN'
                  AND j.status IN ('PENDING', 'LEASED')
                """, (rs, row) -> jobRun(rs), connectionId).stream().findFirst();
    }

    boolean hasSupportedScope(Connection connection) {
        String query = """
                SELECT (? = 'GITHUB' OR EXISTS (
                    SELECT 1 FROM secret_connections c
                    WHERE c.connection_id = ?
                      AND c.auth_ref ~ '^aws-profile:[A-Za-z0-9._-]{1,100}$'
                )) AND EXISTS (
                    SELECT 1 FROM secret_connection_scopes s
                    WHERE s.connection_id = ? AND s.enabled
                      AND (? = 'GITHUB' OR AWS_SCOPE_VALID)
                ) AND (? = 'GITHUB' OR NOT EXISTS (
                    SELECT 1 FROM secret_connection_scopes s
                    WHERE s.connection_id = ? AND s.enabled
                      AND NOT AWS_SCOPE_VALID
                ))
                """.replace("AWS_SCOPE_VALID", AwsScopeSql.predicate("s"));
        Boolean supported = jdbc.queryForObject(query, Boolean.class,
                connection.provider(), connection.id(), connection.id(),
                connection.provider(), connection.provider(), connection.id());
        return Boolean.TRUE.equals(supported);
    }

    OffsetDateTime databaseNow() {
        return jdbc.queryForObject("SELECT clock_timestamp()", OffsetDateTime.class);
    }

    JobRun reserve(Connection connection, long actorId, String idempotencyKey, OffsetDateTime now) {
        Long jobId = jdbc.queryForObject("""
                INSERT INTO secret_jobs
                    (kind, connection_id, requested_by_user_id, idempotency_key, scheduled_at,
                     available_at, attempt_no, max_attempts, status, created_at)
                VALUES ('FULL_SCAN', ?, ?, ?, ?, ?, 0, 3, 'PENDING', ?)
                RETURNING job_id
                """, Long.class, connection.id(), actorId, idempotencyKey, now, now, now);
        Long runId = jdbc.queryForObject("""
                INSERT INTO secret_scan_runs
                    (job_id, connection_id, trigger_type, scope_version, scheduled_at, requested_at,
                     collection_status, detection_status, validation_status, result_status, created_at)
                VALUES (?, ?, 'MANUAL', ?, ?, ?, 'PENDING', 'PENDING', 'PENDING', 'PENDING', ?)
                RETURNING run_id
                """, Long.class, jobId, connection.id(), connection.scopeVersion(), now, now, now);
        int scopeCount = jdbc.update("""
                INSERT INTO secret_run_scopes (run_id, scope_id, collection_status)
                SELECT ?, scope_id, 'PENDING' FROM secret_connection_scopes
                WHERE connection_id = ? AND enabled
                """, runId, connection.id());
        if (scopeCount == 0) {
            throw new NoApprovedScopeException();
        }
        return new JobRun(runId, connection.id(), actorId, idempotencyKey, "PENDING", "PENDING");
    }

    Optional<RunStatus> runStatus(long runId) {
        return jdbc.query("""
                SELECT r.run_id, r.connection_id, r.trigger_type, r.collection_status,
                       r.detection_status, r.validation_status, r.result_status,
                       r.requested_at, r.started_at, r.finished_at, r.failure_code,
                       j.status AS job_status, j.attempt_no, j.max_attempts, j.available_at,
                       j.last_error_code,
                       scope_totals.scope_count, scope_totals.completed_count,
                       scope_totals.incomplete_count, scope_totals.object_count
                FROM secret_scan_runs r JOIN secret_jobs j ON j.job_id = r.job_id
                CROSS JOIN LATERAL (
                    SELECT COUNT(*) AS scope_count,
                           COUNT(*) FILTER (WHERE s.collection_status IN
                               ('SUCCEEDED', 'PARTIAL', 'FAILED', 'SKIPPED')) AS completed_count,
                           COUNT(*) FILTER (WHERE s.collection_status IN
                               ('PARTIAL', 'FAILED', 'SKIPPED')) AS incomplete_count,
                           COALESCE(SUM(s.object_count), 0) AS object_count
                    FROM secret_run_scopes s WHERE s.run_id = r.run_id
                ) scope_totals
                WHERE r.run_id = ?
                """, (rs, row) -> new RunStatus(
                rs.getLong("run_id"), rs.getLong("connection_id"), rs.getString("trigger_type"),
                rs.getString("job_status"), rs.getString("collection_status"),
                rs.getString("detection_status"), rs.getString("validation_status"),
                rs.getString("result_status"), rs.getLong("scope_count"),
                rs.getLong("completed_count"), rs.getLong("incomplete_count"),
                rs.getLong("object_count"), rs.getInt("attempt_no"), rs.getInt("max_attempts"),
                rs.getObject("requested_at", OffsetDateTime.class),
                rs.getObject("started_at", OffsetDateTime.class),
                rs.getObject("finished_at", OffsetDateTime.class),
                rs.getObject("available_at", OffsetDateTime.class),
                rs.getString("failure_code"), rs.getString("last_error_code")), runId)
                .stream().findFirst();
    }

    List<RunScope> runScopes(long runId) {
        return jdbc.query("""
                SELECT rs.run_scope_id, s.content_type, s.approved_ref,
                       rs.collection_status, rs.object_count, rs.failure_code,
                       rs.unsupported_reason
                FROM secret_run_scopes rs
                JOIN secret_connection_scopes s ON s.scope_id = rs.scope_id
                WHERE rs.run_id = ?
                ORDER BY rs.run_scope_id
                """, (rs, row) -> new RunScope(rs.getLong("run_scope_id"),
                rs.getString("content_type"), rs.getString("approved_ref"),
                rs.getString("collection_status"), rs.getObject("object_count", Long.class),
                rs.getString("failure_code"), rs.getString("unsupported_reason")), runId);
    }

    private static JobRun jobRun(ResultSet rs) throws SQLException {
        Long requestedBy = rs.getObject("requested_by_user_id", Long.class);
        return new JobRun(rs.getLong("run_id"), rs.getLong("connection_id"), requestedBy,
                rs.getString("idempotency_key"), rs.getString("job_status"),
                rs.getString("result_status"));
    }

    record Actor(long id, String role) {
    }

    record Connection(long id, String provider, String status, long scopeVersion) {
    }

    record JobRun(long runId, long connectionId, Long requestedBy, String idempotencyKey,
                  String jobStatus, String resultStatus) {
    }

    record RunStatus(long runId, long connectionId, String triggerType, String jobStatus,
                     String collectionStatus, String detectionStatus, String validationStatus,
                     String resultStatus, long scopeCount, long completedScopeCount,
                     long incompleteScopeCount, long objectCount, int attemptNo, int maxAttempts,
                     OffsetDateTime requestedAt, OffsetDateTime startedAt, OffsetDateTime finishedAt,
                     OffsetDateTime availableAt, String runFailureCode, String jobFailureCode) {
    }

    record RunScope(long runScopeId, String contentType, String approvedRef,
                    String collectionStatus, Long objectCount, String failureCode,
                    String unsupportedReason) {
        @Override public String toString() {
            return "RunScope[runScopeId=" + runScopeId + ", collectionStatus=" + collectionStatus + "]";
        }
    }

    static class NoApprovedScopeException extends RuntimeException {
    }
}
