package com.logssey.secretworker;

import java.time.OffsetDateTime;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class SecretScheduleRepository {

    private final JdbcTemplate jdbc;
    private final boolean awsCollectionEnabled;

    @Autowired
    public SecretScheduleRepository(JdbcTemplate jdbc,
                                    @Value("${logssey.secret.aws.collection.enabled:false}")
                                    boolean awsCollectionEnabled) {
        this.jdbc = jdbc;
        this.awsCollectionEnabled = awsCollectionEnabled;
    }

    public SecretScheduleRepository(JdbcTemplate jdbc) {
        this(jdbc, false);
    }

    public OffsetDateTime databaseNow() {
        return jdbc.queryForObject("SELECT CURRENT_TIMESTAMP", OffsetDateTime.class);
    }

    // Must be called within the transaction that inserts the job and advances next_due_at.
    public List<DueConnection> lockDueConnections(OffsetDateTime now, int limit) {
        String query = """
                SELECT c.connection_id, c.scope_version, c.next_due_at
                FROM secret_connections c
                WHERE c.status = 'ACTIVE'
                  AND (c.provider = 'GITHUB' OR (? AND c.provider = 'AWS'
                       AND c.auth_ref ~ '^aws-profile:[A-Za-z0-9._-]{1,100}$'))
                  AND c.next_due_at <= ?
                  AND EXISTS (
                    SELECT 1 FROM secret_connection_scopes s
                    WHERE s.connection_id = c.connection_id AND s.enabled
                      AND (c.provider = 'GITHUB' OR AWS_SCOPE_VALID)
                  )
                  AND (c.provider = 'GITHUB' OR NOT EXISTS (
                    SELECT 1 FROM secret_connection_scopes unsupported
                    WHERE unsupported.connection_id = c.connection_id AND unsupported.enabled
                      AND NOT AWS_UNSUPPORTED_SCOPE_VALID
                  ))
                  AND NOT EXISTS (
                    SELECT 1 FROM secret_jobs j
                    WHERE j.connection_id = c.connection_id
                      AND j.status IN ('PENDING', 'LEASED')
                  )
                ORDER BY c.next_due_at, c.connection_id
                LIMIT ? FOR UPDATE OF c SKIP LOCKED
                """.replace("AWS_SCOPE_VALID", supportedAwsScope("s"))
                .replace("AWS_UNSUPPORTED_SCOPE_VALID", supportedAwsScope("unsupported"));
        return jdbc.query(query, (rs, row) -> new DueConnection(rs.getLong("connection_id"),
                rs.getLong("scope_version"), rs.getObject("next_due_at", OffsetDateTime.class)),
                awsCollectionEnabled, now, limit);
    }

    private static String supportedAwsScope(String alias) {
        String region = "[a-z]{2}(-[a-z0-9]+){1,3}-[0-9]+";
        // Kept in sync with the API's AwsScopeSql. The content processor performs
        // the stricter ARN/account/region/object-key checks before any value read.
        String exactSegment = "([^/?#%*]|%[0-9A-Fa-f]{2})+";
        return "(" + alias + ".history_limit IS NULL AND " + alias + ".content_type = 'IAM_ACCESS_KEY_METADATA'"
                + " AND " + alias + ".approved_ref ~ '^aws://[0-9]{12}/global/iam/access-keys$'"
                + " OR " + alias + ".history_limit = 'CURRENT_STATE_ONLY' AND ("
                + "(" + alias + ".content_type = 'IAM_ACCESS_KEY_METADATA' AND " + alias
                + ".approved_ref ~ '^aws://[0-9]{12}/global/iam/access-keys$')"
                + " OR (" + alias + ".content_type = 'AWS_SECRETS_MANAGER_METADATA' AND " + alias
                + ".approved_ref ~ '^aws://[0-9]{12}/" + region + "/secrets-manager/all$')"
                + " OR (" + alias + ".content_type = 'AWS_SSM_PARAMETER_METADATA' AND " + alias
                + ".approved_ref ~ '^aws://[0-9]{12}/" + region + "/ssm/parameters$')"
                + " OR (" + alias + ".content_type = 'AWS_S3_BUCKET_METADATA' AND " + alias
                + ".approved_ref ~ '^aws://[0-9]{12}/global/s3/buckets$')"
                + ") OR (" + alias + ".history_limit = 'CURRENT_VALUE_ONLY'"
                + " AND char_length(" + alias + ".approved_ref) <= 500 AND ("
                + "(" + alias + ".content_type = 'AWS_SECRETS_MANAGER_VALUE' AND " + alias
                + ".approved_ref ~ '^aws://[0-9]{12}/" + region
                + "/secrets-manager/secret/" + exactSegment + "$')"
                + " OR (" + alias + ".content_type = 'AWS_SSM_PARAMETER_VALUE' AND " + alias
                + ".approved_ref ~ '^aws://[0-9]{12}/" + region
                + "/ssm/parameter/" + exactSegment + "$')"
                + " OR (" + alias + ".content_type = 'AWS_S3_OBJECT_CONTENT' AND " + alias
                + ".approved_ref ~ '^aws://[0-9]{12}/" + region
                + "/s3/object/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/" + exactSegment + "$')"
                + ")))";
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
