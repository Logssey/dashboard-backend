package com.logssey.secret.response;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/** A committed dispatch charge survives HTTP failure, process restart and caller rollback. */
@Component
class SecretAiCallBudget {
    private static final long LOCK_KEY = 72526046L;
    private static final int CALLS_PER_MINUTE = 6;
    private static final int CALLS_PER_DAY = 100;
    private static final Map<String, Set<String>> MODELS = Map.of(
            "CLAUDE", Set.of("claude-sonnet-5-5"),
            "GROQ", Set.of("openai/gpt-oss-20b"));
    private static final Set<String> PURPOSES = Set.of("GUIDE", "BRIEFING");
    private final JdbcTemplate jdbc;
    private final TransactionTemplate transaction;

    SecretAiCallBudget(JdbcTemplate jdbc, PlatformTransactionManager manager) {
        this.jdbc = Objects.requireNonNull(jdbc);
        transaction = new TransactionTemplate(Objects.requireNonNull(manager));
        transaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        transaction.setIsolationLevel(TransactionDefinition.ISOLATION_READ_COMMITTED);
        transaction.setTimeout(3);
    }

    Permit acquire(String provider, String model, String purpose, Duration timeout) {
        if (model == null || !MODELS.getOrDefault(provider == null ? "" : provider, Set.of()).contains(model)
                || !PURPOSES.contains(purpose == null ? "" : purpose)
                || timeout == null || timeout.isZero() || timeout.isNegative()
                || timeout.compareTo(Duration.ofMinutes(1)) > 0) {
            return Permit.denied("CONFIGURATION_INVALID");
        }
        try {
            Permit permit = transaction.execute(status -> {
                jdbc.queryForObject("SELECT pg_advisory_xact_lock(?)", Object.class, LOCK_KEY);
                OffsetDateTime now = jdbc.queryForObject("SELECT clock_timestamp()", OffsetDateTime.class);
                var usage = jdbc.queryForObject("""
                        SELECT
                          EXISTS(SELECT 1 FROM secret_ai_call_ledger
                            WHERE completed_at IS NULL AND deadline_at>?) AS active,
                          (SELECT count(*) FROM secret_ai_call_ledger
                            WHERE reserved_at>?::timestamptz-interval '1 minute') AS minute_calls,
                          (SELECT count(*) FROM secret_ai_call_ledger
                            WHERE reserved_at>=date_trunc('day',?::timestamptz AT TIME ZONE 'UTC')
                              AT TIME ZONE 'UTC') AS day_calls
                        """, (rs, row) -> new Usage(rs.getBoolean("active"),
                        rs.getLong("minute_calls"), rs.getLong("day_calls")), now, now, now);
                if (usage.active()) return Permit.denied("REQUEST_IN_PROGRESS");
                if (usage.minuteCalls() >= CALLS_PER_MINUTE || usage.dayCalls() >= CALLS_PER_DAY) {
                    return Permit.denied("CALL_BUDGET_EXHAUSTED");
                }
                UUID id = UUID.randomUUID();
                OffsetDateTime deadline = now.plus(timeout).plusSeconds(15);
                jdbc.update("""
                        INSERT INTO secret_ai_call_ledger
                          (call_id,provider,model,purpose,state,reserved_at,deadline_at)
                        VALUES(?,?,?,?,'DISPATCHING',?,?)
                        """, id, provider, model, purpose, now, deadline);
                return new Permit(true, "READY", () -> complete(id));
            });
            return permit == null ? Permit.denied("CALL_BUDGET_UNAVAILABLE") : permit;
        } catch (RuntimeException unavailable) {
            // A failed commit may already have charged the attempt. Never assume it was free.
            return Permit.denied("CALL_BUDGET_UNAVAILABLE");
        }
    }

    private void complete(UUID id) {
        transaction.executeWithoutResult(status -> jdbc.update("""
                UPDATE secret_ai_call_ledger
                SET state='COMPLETED',completed_at=GREATEST(clock_timestamp(),reserved_at)
                WHERE call_id=? AND completed_at IS NULL
                """, id));
    }

    private record Usage(boolean active, long minuteCalls, long dayCalls) {}

    static final class Permit implements AutoCloseable {
        private final boolean allowed;
        private final String reasonCode;
        private final Runnable completion;
        private final AtomicBoolean closed = new AtomicBoolean();

        private Permit(boolean allowed, String reasonCode, Runnable completion) {
            this.allowed = allowed;
            this.reasonCode = reasonCode;
            this.completion = completion;
        }

        private static Permit denied(String reasonCode) {
            return new Permit(false, reasonCode, () -> {});
        }

        /** Available only to injected HTTP tests. Production constructors require the DB budget. */
        static Permit unmeteredForTests() {
            return new Permit(true, "READY", () -> {});
        }

        boolean allowed() { return allowed; }
        String reasonCode() { return reasonCode; }

        @Override
        public void close() {
            if (!closed.compareAndSet(false, true)) return;
            try { completion.run(); }
            catch (RuntimeException unavailable) {
                // Keep the dispatch charge and active deadline when completion is uncertain.
            }
        }
    }
}
