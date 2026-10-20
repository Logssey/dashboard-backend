package com.logssey.secret.command;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.function.Supplier;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.access.SecretPrincipal;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Serializes retries and commits the mutation, controlled result and audit atomically. */
@Service
public class SecretCommandExecutor {
    public enum Kind {
        MANUAL_SCAN("RUN", "MANUAL_SCAN_REGISTERED");

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
                    VALUES (?, ?, ?, ?, ?, ?, jsonb_build_object('status', ?::text))
                    """, kind.auditEvent, actor.userId(), kind.targetType, result.targetId(),
                    result.version(), commandId, result.status().name());
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
