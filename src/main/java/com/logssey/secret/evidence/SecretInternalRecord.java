package com.logssey.secret.evidence;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/** A reference to an actual, immutable user action, never proof of verification by itself. */
public final class SecretInternalRecord {
    private SecretInternalRecord() {}

    public static String reference(JdbcTemplate jdbc, String provided, long actor, String targetType,
                                   long targetId, long targetVersion, String event) {
        if (provided != null) {
            rejectReserved(provided);
            return provided;
        }
        if (!TransactionSynchronizationManager.isActualTransactionActive())
            throw new IllegalStateException("TRANSACTION_REQUIRED");
        long id = jdbc.queryForObject("""
            INSERT INTO secret_internal_records(actor_user_id,target_type,target_id,target_version,event_code)
            VALUES(?,?,?,?,?) RETURNING record_id
            """, Long.class, actor, targetType, targetId, targetVersion, event);
        // Retains the historical reference format, but resolves to a real local record.
        return "CHANGE:RECORD-" + id;
    }

    public static void rejectReserved(String value) {
        if (value != null && value.startsWith("CHANGE:RECORD-"))
            throw new com.logssey.common.error.ApiException(com.logssey.common.error.ErrorCode.INVALID_INPUT);
    }
}
