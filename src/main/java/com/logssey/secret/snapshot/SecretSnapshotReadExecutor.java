package com.logssey.secret.snapshot;

import com.logssey.secret.query.SecretReadConflict;
import java.sql.SQLException;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.function.Supplier;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Retries the entire authorized projection, never just the snapshot insert in an aborted transaction. */
final class SecretSnapshotReadExecutor {
    private static final int MAX_ATTEMPTS = 3;
    private final TransactionTemplate transaction;

    SecretSnapshotReadExecutor(PlatformTransactionManager manager) {
        transaction = new TransactionTemplate(manager);
        transaction.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
    }

    <T> T read(Supplier<T> operation) {
        // An existing caller owns its rollback boundary; it must not be suspended or partially replayed.
        boolean ownsTransaction = !TransactionSynchronizationManager.isActualTransactionActive();
        for (int attempt = 1; ; attempt++) {
            try {
                return transaction.execute(status -> operation.get());
            } catch (RuntimeException failure) {
                if (!isSerializationFailure(failure)) throw failure;
                if (!ownsTransaction || attempt == MAX_ATTEMPTS)
                    throw new SecretReadConflict(SecretReadConflict.Reason.SNAPSHOT_RETRY);
                // execute has completed rollback and released its connection before the next attempt.
            }
        }
    }

    static boolean isSerializationFailure(Throwable failure) {
        var seen = Collections.newSetFromMap(new IdentityHashMap<Throwable, Boolean>());
        for (Throwable cause = failure; cause != null && seen.add(cause); cause = cause.getCause()) {
            if (cause instanceof SQLException sql) {
                for (SQLException current = sql; current != null; current = current.getNextException()) {
                    if ("40001".equals(current.getSQLState())) return true;
                    if (current.getNextException() == current) break;
                }
            }
        }
        return false;
    }
}
