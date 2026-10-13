package com.logssey.secretworker;

import java.time.OffsetDateTime;
import java.util.List;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class SecretScheduleRepository {

    private final JdbcTemplate jdbc;

    public SecretScheduleRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public OffsetDateTime databaseNow() {
        return jdbc.queryForObject("SELECT CURRENT_TIMESTAMP", OffsetDateTime.class);
    }

    // Must be called within the transaction that inserts the job and advances next_due_at.
    public List<DueConnection> lockDueConnections(OffsetDateTime now, int limit) {
        return jdbc.query("""
                SELECT c.connection_id, c.scope_version, c.next_due_at
                FROM secret_connections c
                WHERE c.status = 'ACTIVE' AND c.provider = 'GITHUB' AND c.next_due_at <= ?
                  AND EXISTS (
                    SELECT 1 FROM secret_connection_scopes s
                    WHERE s.connection_id = c.connection_id AND s.enabled
                  )
                  AND NOT EXISTS (
                    SELECT 1 FROM secret_jobs j
                    WHERE j.connection_id = c.connection_id AND j.kind = 'FULL_SCAN'
                      AND j.status IN ('PENDING', 'LEASED')
                  )
                ORDER BY c.next_due_at, c.connection_id
                LIMIT ? FOR UPDATE OF c SKIP LOCKED
                """, (rs, row) -> new DueConnection(rs.getLong("connection_id"),
                rs.getLong("scope_version"), rs.getObject("next_due_at", OffsetDateTime.class)), now, limit);
    }

    public void reserve(DueConnection connection, OffsetDateTime now, SecretSchedulerProperties properties) {
        String idempotencyKey = "full-scan:" + connection.id() + ":" + connection.scheduledAt().toInstant();
        Long jobId = jdbc.queryForObject("""
                INSERT INTO secret_jobs
                    (kind, connection_id, idempotency_key, scheduled_at, available_at,
                     attempt_no, max_attempts, status, created_at)
                VALUES ('FULL_SCAN', ?, ?, ?, ?, 0, ?, 'PENDING', ?)
                RETURNING job_id
                """, Long.class, connection.id(), idempotencyKey, connection.scheduledAt(), now,
                properties.maxAttempts(), now);

        Long runId = jdbc.queryForObject("""
                INSERT INTO secret_scan_runs
                    (job_id, connection_id, trigger_type, scope_version, scheduled_at, requested_at,
                     collection_status, detection_status, validation_status, result_status, created_at)
                VALUES (?, ?, 'SCHEDULED', ?, ?, ?, 'PENDING', 'PENDING', 'PENDING', 'PENDING', ?)
                RETURNING run_id
                """, Long.class, jobId, connection.id(), connection.scopeVersion(), connection.scheduledAt(), now, now);

        jdbc.update("""
                INSERT INTO secret_run_scopes (run_id, scope_id, collection_status)
                SELECT ?, scope_id, 'PENDING' FROM secret_connection_scopes
                WHERE connection_id = ? AND enabled
                """, runId, connection.id());

        jdbc.update("""
                UPDATE secret_connections SET next_due_at = ?, updated_at = ? WHERE connection_id = ?
                """, connection.scheduledAt().plus(properties.scanInterval()), now, connection.id());
    }

    public record DueConnection(long id, long scopeVersion, OffsetDateTime scheduledAt) {
    }
}
