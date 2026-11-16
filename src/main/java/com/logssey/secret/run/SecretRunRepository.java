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

    private static final String RUN_STATUS_SELECT = """
            SELECT r.run_id, r.connection_id, r.trigger_type, r.collection_status,
                   r.detection_status, r.validation_status, r.result_status,
                   r.requested_at, r.started_at, r.finished_at, r.failure_code,
                   j.status AS job_status, j.attempt_no, j.max_attempts,
                   CASE WHEN j.status='PENDING' THEN GREATEST(j.available_at,(
                       SELECT max(retry.source_retry_at) FROM secret_connections retry
                       WHERE c.provider='NOTION' AND retry.provider='NOTION' AND retry.auth_ref=c.auth_ref
                   )) ELSE j.available_at END AS available_at,
                   j.last_error_code, c.provider, c.display_name,
                   scope_totals.scope_count, scope_totals.completed_count,
                   scope_totals.incomplete_count, scope_totals.object_count
            FROM secret_scan_runs r
            JOIN secret_jobs j ON j.job_id = r.job_id
            JOIN secret_connections c ON c.connection_id = r.connection_id
            CROSS JOIN LATERAL (
                SELECT COUNT(*) AS scope_count,
                       COUNT(*) FILTER (WHERE s.collection_status IN
                           ('SUCCEEDED', 'PARTIAL', 'FAILED', 'SKIPPED')) AS completed_count,
                       COUNT(*) FILTER (WHERE s.collection_status IN
                           ('PARTIAL', 'FAILED', 'SKIPPED')) AS incomplete_count,
                       COALESCE(SUM(s.object_count), 0) AS object_count
                FROM secret_run_scopes s WHERE s.run_id = r.run_id
            ) scope_totals
            """;

    private final JdbcTemplate jdbc;

    SecretRunCoverageResponse coverage(long runId,String loginId) {
        var coverage=new SecretScanFactsRepository(jdbc).runCoverage(runId);
        if(coverage.revalidation()==null)return coverage;
        var access=new com.logssey.secret.access.SecretAccessService(jdbc);
        if(access.canReadOccurrence(access.requirePrincipal(loginId),coverage.revalidation().occurrenceId()))return coverage;
        return new SecretRunCoverageResponse(coverage.successfulScopeCount(),coverage.finishedScopeCount(),coverage.gapScopeCount(),
            coverage.unverifiedScopeCount(),coverage.scopeStatusCounts(),coverage.aggregationStatus(),coverage.findingCount(),
            coverage.distinctCredentialCount(),coverage.newCredentialCount(),coverage.newCredentialCountReason(),coverage.coverageComplete(),
            coverage.unit(),coverage.asOf(),null,coverage.provider(),coverage.safeDisplayAlias());
    }
    List<SecretRunScopeResultResponse> safeScopes(long runId) { return new SecretScanFactsRepository(jdbc).scopes(runId); }

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

    boolean hasActiveRevalidation(long connectionId) {
        return Boolean.TRUE.equals(jdbc.queryForObject("""
                SELECT EXISTS (SELECT 1 FROM secret_jobs
                    WHERE connection_id = ? AND kind = 'REVALIDATE'
                      AND status IN ('PENDING', 'LEASED'))
                """, Boolean.class, connectionId));
    }

    boolean hasSupportedScope(Connection connection) {
        if ("NOTION".equals(connection.provider())) {
            String valid = com.logssey.secret.notion.NotionScopeSql.predicate("s");
            return Boolean.TRUE.equals(jdbc.queryForObject(
                    "SELECT EXISTS(SELECT 1 FROM secret_connections WHERE connection_id=?"
                        + " AND auth_ref='notion-internal:default')"
                        + " AND EXISTS(SELECT 1 FROM secret_connection_scopes s WHERE s.connection_id=? AND s.enabled)"
                        + " AND NOT EXISTS(SELECT 1 FROM secret_connection_scopes s WHERE s.connection_id=?"
                        + " AND s.enabled AND (" + valid + ") IS NOT TRUE)",
                    Boolean.class, connection.id(), connection.id(), connection.id()));
        }
        String query = """
                SELECT (? = 'GITHUB' OR EXISTS (
                    SELECT 1 FROM secret_connections c
                    WHERE c.connection_id = ?
                      AND (c.auth_ref ~ '^aws-profile:[A-Za-z0-9._-]{1,100}$' OR c.auth_ref='aws-workload:default')
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
        return reserve(connection, actorId, idempotencyKey, now, List.of());
    }

    JobRun reserve(Connection connection, long actorId, String idempotencyKey, OffsetDateTime now, List<Long> scopeIds) {
        Long jobId = jdbc.queryForObject("""
                INSERT INTO secret_jobs
                    (kind, connection_id, requested_by_user_id, idempotency_key, scheduled_at,
                     available_at, attempt_no, max_attempts, status, created_at)
                VALUES ('FULL_SCAN', ?, ?, ?, ?, GREATEST(?::timestamptz,(
                    SELECT max(retry.source_retry_at) FROM secret_connections source
                    JOIN secret_connections retry ON retry.provider='NOTION' AND retry.auth_ref=source.auth_ref
                    WHERE source.connection_id=? AND source.provider='NOTION'
                )), 0, 3, 'PENDING', ?)
                RETURNING job_id
                """, Long.class, connection.id(), actorId, idempotencyKey, now, now, connection.id(), now);
        Long runId = jdbc.queryForObject("""
                INSERT INTO secret_scan_runs
                    (job_id, connection_id, trigger_type, scope_version, scheduled_at, requested_at,
                     collection_status, detection_status, validation_status, result_status, created_at)
                VALUES (?, ?, 'MANUAL', ?, ?, ?, 'PENDING', 'PENDING', 'PENDING', 'PENDING', ?)
                RETURNING run_id
                """, Long.class, jobId, connection.id(), connection.scopeVersion(), now, now, now);
        String selectedScopes = scopeIds.isEmpty() ? "" : " AND scope_id IN ("
                + String.join(",", java.util.Collections.nCopies(scopeIds.size(), "?")) + ")";
        var scopeArguments = new java.util.ArrayList<Object>();
        scopeArguments.add(runId);
        scopeArguments.add(connection.id());
        scopeArguments.addAll(scopeIds);
        int scopeCount = jdbc.update("""
                INSERT INTO secret_run_scopes (run_id, scope_id, collection_status)
                SELECT ?, scope_id, 'PENDING' FROM secret_connection_scopes
                WHERE connection_id = ? AND enabled
                """ + selectedScopes, scopeArguments.toArray());
        if (scopeCount == 0) {
            throw new NoApprovedScopeException();
        }
        return new JobRun(runId, connection.id(), actorId, idempotencyKey, "PENDING", "PENDING");
    }

    void linkRetry(long runId,long sourceRunId) {
        jdbc.update("UPDATE secret_scan_runs SET retry_of_run_id=? WHERE run_id=?",sourceRunId,runId);
    }

    Optional<RetryContext> retryContext(long runId) {
        return jdbc.query("""
                SELECT r.connection_id,r.scope_version,j.kind,j.status
                FROM secret_scan_runs r JOIN secret_jobs j ON j.job_id=r.job_id WHERE r.run_id=?
                """, (rs,n) -> new RetryContext(rs.getLong("connection_id"),rs.getLong("scope_version"),
                rs.getString("kind"),rs.getString("status")),runId).stream().findFirst();
    }

    List<Long> retryScopes(long runId) {
        return jdbc.queryForList("""
                SELECT rs.scope_id FROM secret_scope_outcomes rs
                JOIN secret_connection_scopes s ON s.scope_id=rs.scope_id
                WHERE rs.run_id=? AND s.enabled AND s.revision=rs.scope_revision
                  AND rs.scope_outcome IN ('PARTIAL','FAILED','SKIPPED') ORDER BY rs.scope_id
                """,Long.class,runId);
    }

    record RetryContext(long connectionId,long scopeVersion,String kind,String jobStatus) { }

    Optional<RunStatus> runStatus(long runId) {
        return jdbc.query(RUN_STATUS_SELECT + "WHERE r.run_id = ?",
                (rs, row) -> runStatus(rs), runId).stream().findFirst();
    }

    long countRuns(long userId) {
        return jdbc.queryForObject("SELECT COUNT(*) FROM secret_scan_runs r WHERE " + READABLE_RUN,
                Long.class, userId);
    }

    private static final String READABLE_RUN = """
            EXISTS (SELECT 1 FROM secret_role_grants g
                WHERE g.user_id = ? AND g.revoked_at IS NULL
                  AND g.role IN ('SECURITY', 'OPERATIONS')
                  AND (g.connection_id IS NULL OR g.connection_id = r.connection_id))
            """;

    List<RunListEntry> listRuns(long userId, int size, long offset) {
        return jdbc.query(RUN_STATUS_SELECT + "WHERE " + READABLE_RUN
                        + " ORDER BY r.requested_at DESC, r.run_id DESC LIMIT ? OFFSET ?",
                (rs, row) -> new RunListEntry(runStatus(rs), rs.getString("provider"),
                        rs.getString("display_name")), userId, size, offset);
    }

    private static RunStatus runStatus(ResultSet rs) throws SQLException {
        return new RunStatus(
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
                rs.getString("failure_code"), rs.getString("last_error_code"));
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

    record RunListEntry(RunStatus status, String provider, String displayName) {
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
