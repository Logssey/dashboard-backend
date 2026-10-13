package com.logssey.secretworker.aws;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Objects;

import org.springframework.jdbc.core.JdbcTemplate;

import com.logssey.secretworker.ClaimedSecretJob;
import com.logssey.secretworker.SecretJobExecutionService;

/** Stores keyed metadata and observations only; never the access-key ID or source credentials. */
public final class AwsIamMetadataRepository {
    private final JdbcTemplate jdbc;
    private final AwsMetadataIdentity identity;

    public AwsIamMetadataRepository(JdbcTemplate jdbc, AwsMetadataIdentity identity) {
        this.jdbc = jdbc;
        this.identity = identity;
    }

    public boolean recordIfLeased(ClaimedSecretJob job, SecretJobExecutionService execution,
                                  long scopeId, AwsApprovedScope approved,
                                  AwsIamGateway.AccessKey key, AwsIamGateway.LastUsed usage) {
        return execution.persistIfLeased(job.jobId(), job.leaseToken(), () -> {
            var now = Instant.now();
            String ref = identity.reference(approved.accountId(), key.id());
            String source = "aws://" + approved.accountId() + "/global/iam/access-key/" + ref;
            String label = key.id().length() >= 4
                    ? "AWS IAM access key ····" + key.id().substring(key.id().length() - 4)
                    : "AWS IAM access key";
            Long credentialId = jdbc.queryForObject("""
                    INSERT INTO secret_credential_sets
                        (issuer, credential_type, component_state, issuer_connection_id,
                         external_key_ref, masked_label, issued_at, first_seen_at, last_seen_at)
                    VALUES ('AWS', 'AWS_IAM_ACCESS_KEY', 'METADATA_ONLY', ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (issuer, credential_type, issuer_connection_id, external_key_ref)
                        WHERE component_state = 'METADATA_ONLY' AND issuer = 'AWS'
                    DO UPDATE SET last_seen_at = GREATEST(secret_credential_sets.last_seen_at,
                        EXCLUDED.last_seen_at)
                    RETURNING credential_set_id
                    """, Long.class, job.connectionId(), ref, label,
                    utc(key.createdAt()), utc(now), utc(now));
            credentialId = Objects.requireNonNull(credentialId);
            jdbc.update("""
                    INSERT INTO secret_occurrences
                        (credential_set_id, connection_id, scope_id, source_object_ref,
                         location_key, environment, exposure_status, exposure_range,
                         presence_status, first_seen_at, last_seen_at, last_seen_run_id)
                    VALUES (?, ?, ?, ?, 'iam/access-key', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN',
                            'PRESENT', ?, ?, ?)
                    ON CONFLICT (credential_set_id, connection_id, source_object_ref, location_key)
                    DO UPDATE SET last_seen_at = GREATEST(secret_occurrences.last_seen_at,
                        EXCLUDED.last_seen_at), last_seen_run_id = EXCLUDED.last_seen_run_id,
                        presence_status = 'PRESENT'
                    """, credentialId, job.connectionId(), scopeId, source,
                    utc(now), utc(now), job.runId());
            jdbc.update("""
                    INSERT INTO secret_aws_access_key_observations
                        (credential_set_id, run_id, key_status, issued_at, last_used_at,
                         last_used_service, last_used_region, observed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (credential_set_id, run_id)
                    DO UPDATE SET key_status = EXCLUDED.key_status,
                        last_used_at = EXCLUDED.last_used_at,
                        last_used_service = EXCLUDED.last_used_service,
                        last_used_region = EXCLUDED.last_used_region,
                        observed_at = EXCLUDED.observed_at
                    """, credentialId, job.runId(), safeStatus(key.status()),
                    utc(key.createdAt()), utc(usage.at()), safeService(usage.service()),
                    safeRegion(usage.region()), utc(now));
        });
    }

    /** Absence is meaningful only after the entire approved IAM listing succeeds. */
    public boolean markCompleteCoverageIfLeased(ClaimedSecretJob job,
                                                 SecretJobExecutionService execution,
                                                 long scopeId) {
        return execution.persistIfLeased(job.jobId(), job.leaseToken(), () -> jdbc.update("""
                UPDATE secret_occurrences o
                SET presence_status = CASE WHEN o.last_seen_run_id = ? THEN 'PRESENT' ELSE 'MISSING' END,
                    last_complete_coverage_at = ?
                FROM secret_credential_sets c
                WHERE o.credential_set_id = c.credential_set_id
                  AND o.connection_id = ? AND o.scope_id = ?
                  AND c.issuer = 'AWS' AND c.credential_type = 'AWS_IAM_ACCESS_KEY'
                  AND c.component_state = 'METADATA_ONLY'
                """, job.runId(), utc(Instant.now()), job.connectionId(), scopeId));
    }

    private static String safeStatus(String value) {
        if (value == null) return "UNKNOWN";
        return switch (value.toUpperCase(java.util.Locale.ROOT)) {
            case "ACTIVE", "INACTIVE", "EXPIRED" -> value.toUpperCase(java.util.Locale.ROOT);
            default -> "UNKNOWN";
        };
    }

    private static String safeService(String value) {
        return value != null && value.matches("[A-Za-z0-9 ._/-]{1,120}") && !"N/A".equals(value)
                ? value : null;
    }

    private static String safeRegion(String value) {
        return value != null && value.matches("[a-z0-9-]{1,80}") && !"N/A".equals(value)
                ? value : null;
    }

    private static OffsetDateTime utc(Instant value) {
        return value == null ? null : value.atOffset(ZoneOffset.UTC);
    }
}
