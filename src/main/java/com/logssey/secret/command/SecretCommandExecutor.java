package com.logssey.secret.command;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.access.SecretPrincipal;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.function.Supplier;

/** Serializes retries and commits the mutation, controlled result and audit atomically. */
@Service
public class SecretCommandExecutor {
    public enum Kind {
        MANUAL_SCAN("RUN", "MANUAL_SCAN_REGISTERED"),
        CREDENTIAL_VALIDATION("VALIDATION_REQUEST", "CREDENTIAL_VALIDATION_REQUESTED"),
        VALIDATION_POLICY("SCOPE", "VALIDATION_POLICY_CHANGED"),
        CONNECTION_VALIDATION_POLICY("CONNECTION", "VALIDATION_PROFILE_CHANGED"),
        SCOPE_CLASSIFICATION("SCOPE_PROPOSAL", "CLASSIFICATION_PROPOSED"),
        SCOPE_CLASSIFICATION_APPROVE("SCOPE_PROPOSAL", "CLASSIFICATION_APPROVED"),
        SCOPE_CLASSIFICATION_REJECT("SCOPE_PROPOSAL", "CLASSIFICATION_REJECTED"),
        SCOPE_REVIEWER_ASSIGN("SCOPE_PROPOSAL", "CLASSIFICATION_REVIEWER_ASSIGNED"),
        INVESTIGATION_REQUEST("INVESTIGATION", "INVESTIGATION_REQUESTED"),
        INVESTIGATION_ACCEPT("INVESTIGATION", "INVESTIGATION_EVIDENCE_ACCEPTED"),
        INVESTIGATION_ASSIGN("INVESTIGATION", "INVESTIGATION_ASSIGNED"),
        INVESTIGATION_EVIDENCE("INVESTIGATION", "INVESTIGATION_EVIDENCE_ADDED"),
        INVESTIGATION_CLOSE("INVESTIGATION", "INVESTIGATION_CLOSED"),
        FIXTURE_ATTEST("FIXTURE_ATTESTATION", "FIXTURE_ATTESTED"),
        CROSS_ALERT_ASSIGN("CROSS_ALERT", "CROSS_ALERT_ASSIGNED"),
        CROSS_ALERT_ACK("CROSS_ALERT", "CROSS_ALERT_ACKNOWLEDGED"),
        CROSS_ALERT_CLOSE("CROSS_ALERT", "CROSS_ALERT_CLOSED"),
        LOCATION_ACTION("CASE", "LOCATION_ACTION_RECORDED"),
        COMPLETE_LOCATION_ACTIONS("CASE", "LOCATION_ACTIONS_COMPLETED"),
        LOCATION_REVALIDATE("REVALIDATION", "LOCATION_REVALIDATION_REQUESTED"),
        LOCATION_RESUME("CASE", "LOCATION_REVALIDATION_RESUMED"),
        LIFECYCLE_SUBMIT("LIFECYCLE_EVIDENCE", "LIFECYCLE_EVIDENCE_SUBMITTED"),
        LIFECYCLE_REVIEW("LIFECYCLE_EVIDENCE", "LIFECYCLE_EVIDENCE_REVIEWED"),
        CASE_RESOLUTION("CASE", "CASE_RESOLUTION_CONFIRMED"),
        CASE_DISMISSAL("CASE_DISMISSAL", "CASE_DISMISSED"),
        RISK_EXCEPTION_APPROVE("RISK_EXCEPTION", "RISK_EXCEPTION_APPROVED"),
        RISK_EXCEPTION_REVOKE("RISK_EXCEPTION", "RISK_EXCEPTION_REVOKED"),
        TRANSFER_SUBMIT("TRANSFER_EVIDENCE", "TRANSFER_EVIDENCE_SUBMITTED"),
        TRANSFER_REVIEW("TRANSFER_EVIDENCE", "TRANSFER_EVIDENCE_REVIEWED");

        private final String targetType;
        private final String auditEvent;
        Kind(String targetType, String auditEvent) {
            this.targetType = targetType;
            this.auditEvent = auditEvent;
        }
    }

    private final JdbcTemplate jdbc;
    private final TransactionTemplate transaction;

    public SecretCommandExecutor(JdbcTemplate jdbc, PlatformTransactionManager transactionManager) {
        this.jdbc = jdbc;
        this.transaction = new TransactionTemplate(transactionManager);
    }

    /** Callers pass a digest of validated, normalized safe fields, never raw request content. */
    public SecretCommandResult execute(SecretPrincipal actor, Kind kind, String idempotencyKey,
                                        byte[] safeRequestDigest, Runnable authorize,
                                        Supplier<SecretCommandResult> mutation) {
        if (actor == null || kind == null || idempotencyKey == null
                || !idempotencyKey.matches("[A-Za-z0-9._:-]{1,120}")
                || safeRequestDigest == null || safeRequestDigest.length != 32) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        byte[] requestDigest = safeRequestDigest.clone();
        // Persist a key digest, not the caller-provided idempotency text.
        String keyDigest = HexFormat.of().formatHex(sha256(idempotencyKey.getBytes(StandardCharsets.US_ASCII)));
        return Objects.requireNonNull(transaction.execute(ignored -> {
            byte[] lockDigest = sha256((actor.userId() + ":" + kind.name() + ":" + keyDigest)
                    .getBytes(StandardCharsets.US_ASCII));
            jdbc.queryForObject("SELECT pg_advisory_xact_lock(?)", Object.class,
                    ByteBuffer.wrap(lockDigest).getLong());
            // Replay must not bypass a grant revoked since the original command.
            authorize.run();
            var previous = jdbc.query("""
                    SELECT safe_request_digest,
                           (safe_result->>'targetId')::bigint AS target_id,
                           (safe_result->>'version')::bigint AS target_version,
                           safe_result->>'status' AS status
                    FROM secret_command_idempotency
                    WHERE actor_user_id = ? AND command_kind = ? AND idempotency_key = ?
                    """, (rs, row) -> new Previous(rs.getBytes("safe_request_digest"),
                    new SecretCommandResult(rs.getLong("target_id"), rs.getLong("target_version"),
                            SecretCommandResult.Status.valueOf(rs.getString("status")))),
                    actor.userId(), kind.name(), keyDigest).stream().findFirst();
            if (previous.isPresent()) {
                if (!MessageDigest.isEqual(previous.orElseThrow().digest(), requestDigest))
                    throw new ApiException(ErrorCode.CONFLICT);
                return previous.orElseThrow().result();
            }
            SecretCommandResult result = Objects.requireNonNull(mutation.get());
            long commandId = jdbc.queryForObject("""
                    INSERT INTO secret_command_idempotency
                        (actor_user_id, command_kind, idempotency_key, safe_request_digest, safe_result)
                    VALUES (?, ?, ?, ?, jsonb_build_object(
                        'targetId', ?::bigint, 'version', ?::bigint, 'status', ?::text,
                        'requiresSnapshotRefresh', true)) RETURNING command_id
                    """, Long.class, actor.userId(), kind.name(), keyDigest, requestDigest,
                    result.targetId(), result.version(), result.status().name());
            jdbc.update("""
                    INSERT INTO secret_audit_events
                        (event_type, actor_user_id, target_type, target_id, target_version,
                         command_id, safe_changes)
                    VALUES (?, ?, ?, ?, ?, ?, jsonb_build_object('status', ?::text) || COALESCE((
                        SELECT jsonb_build_object('enabled',c.validation_enabled,
                            'allowedIssuers',to_jsonb(c.validation_allowed_issuers),
                            'profile',c.validation_profile_version)
                        FROM secret_connections c WHERE c.connection_id=? AND c.validation_revision=?
                          AND ?::text='CONNECTION_VALIDATION_POLICY'
                    ),'{}'::jsonb))
                    """, kind.auditEvent, actor.userId(), kind.targetType, result.targetId(),
                    result.version(), commandId, result.status().name(), result.targetId(), result.version(), kind.name());
            return result;
        }));
    }

    /** Call while holding the target lock; the conditional UPDATE must also match its version. */
    public static void requireExpectedVersion(Long expectedVersion, long actualVersion) {
        if (expectedVersion == null || expectedVersion < 0) throw new ApiException(ErrorCode.INVALID_INPUT);
        if (expectedVersion != actualVersion) throw new ApiException(ErrorCode.CONFLICT);
    }

    public static byte[] digestSafeIds(long... values) {
        ByteBuffer bytes = ByteBuffer.allocate(values.length * Long.BYTES);
        for (long value : values) bytes.putLong(value);
        return sha256(bytes.array());
    }

    private static byte[] sha256(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable");
        }
    }

    private record Previous(byte[] digest, SecretCommandResult result) { }
}
