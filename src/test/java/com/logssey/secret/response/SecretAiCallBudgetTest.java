package com.logssey.secret.response;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

class SecretAiCallBudgetTest {
    private static final PostgreSQLContainer POSTGRES = new com.logssey.secret.testing.SecretTestPostgres();
    private static final Duration TIMEOUT = Duration.ofSeconds(45);
    private static JdbcTemplate jdbc;
    private static DataSourceTransactionManager transactions;
    private SecretAiCallBudget first;
    private SecretAiCallBudget second;

    @BeforeAll
    static void database() {
        POSTGRES.start();
        var source = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(source).load().migrate();
        jdbc = new JdbcTemplate(source);
        transactions = new DataSourceTransactionManager(source);
    }

    @AfterAll
    static void stopDatabase() { POSTGRES.stop(); }

    @BeforeEach
    void prepare() {
        jdbc.execute("TRUNCATE secret_ai_call_ledger");
        first = new SecretAiCallBudget(jdbc, transactions);
        second = new SecretAiCallBudget(jdbc, transactions);
    }

    @Test
    void providersFeaturesAndReplicasShareOneLiveReservationAndCompletionIsIdempotent() {
        var claude = first.acquire("CLAUDE", "claude-sonnet-5-5", "GUIDE", TIMEOUT);
        assertThat(claude.allowed()).isTrue();
        var groq = second.acquire("GROQ", "openai/gpt-oss-20b", "BRIEFING", Duration.ofSeconds(5));
        assertThat(groq.allowed()).isFalse();
        assertThat(groq.reasonCode()).isEqualTo("REQUEST_IN_PROGRESS");
        assertThat(count()).isEqualTo(1);

        claude.close();
        var completedAt = jdbc.queryForObject("SELECT completed_at::text FROM secret_ai_call_ledger", String.class);
        claude.close();
        assertThat(jdbc.queryForObject("SELECT completed_at::text FROM secret_ai_call_ledger", String.class)).isEqualTo(completedAt);
        try (var next = second.acquire("GROQ", "openai/gpt-oss-20b", "BRIEFING", Duration.ofSeconds(5))) {
            assertThat(next.allowed()).isTrue();
        }
        assertThat(count()).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_ai_call_ledger WHERE state='COMPLETED'", Long.class)).isEqualTo(2);
    }

    @Test
    void completingRequestsKeepsEveryChargeInTheSharedMinuteBudget() {
        for (int call = 0; call < 6; call++) {
            var budget = call % 2 == 0 ? first : second;
            try (var permit = budget.acquire("CLAUDE", "claude-sonnet-5-5", "GUIDE", TIMEOUT)) {
                assertThat(permit.allowed()).isTrue();
            }
        }
        var denied = second.acquire("GROQ", "openai/gpt-oss-20b", "BRIEFING", Duration.ofSeconds(5));
        assertThat(denied.allowed()).isFalse();
        assertThat(denied.reasonCode()).isEqualTo("CALL_BUDGET_EXHAUSTED");
        assertThat(count()).isEqualTo(6);
    }

    @Test
    void completedCallsRemainChargedAgainstTheUtcDailyLimit() {
        jdbc.update("""
                INSERT INTO secret_ai_call_ledger
                  (call_id,provider,model,purpose,state,reserved_at,deadline_at,completed_at)
                SELECT gen_random_uuid(),'CLAUDE','claude-sonnet-5-5','GUIDE','COMPLETED',
                  date_trunc('day',clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC',
                  (date_trunc('day',clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC')+interval '60 seconds',
                  date_trunc('day',clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'
                FROM generate_series(1,100)
                """);
        var denied = second.acquire("GROQ", "openai/gpt-oss-20b", "BRIEFING", Duration.ofSeconds(5));
        assertThat(denied.allowed()).isFalse();
        assertThat(denied.reasonCode()).isEqualTo("CALL_BUDGET_EXHAUSTED");
        assertThat(count()).isEqualTo(100);
    }

    @Test
    void anExpiredOrLostReservationReleasesConcurrencyWhileKeepingItsCharge() {
        var lost = first.acquire("CLAUDE", "claude-sonnet-5-5", "GUIDE", TIMEOUT);
        assertThat(lost.allowed()).isTrue();
        jdbc.update("""
                UPDATE secret_ai_call_ledger SET reserved_at=clock_timestamp()-interval '2 minutes',
                  deadline_at=clock_timestamp()-interval '1 minute'
                """);
        try (var next = second.acquire("GROQ", "openai/gpt-oss-20b", "BRIEFING", Duration.ofSeconds(5))) {
            assertThat(next.allowed()).isTrue();
        }
        assertThat(count()).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_ai_call_ledger WHERE state='DISPATCHING'", Long.class)).isEqualTo(1);
        lost.close();
    }

    @Test
    void callerRollbackAndANewProcessCannotRefundADispatch() {
        var caller = new TransactionTemplate(transactions);
        var permit = caller.execute(status -> {
            var acquired = first.acquire("CLAUDE", "claude-sonnet-5-5", "GUIDE", TIMEOUT);
            status.setRollbackOnly();
            return acquired;
        });
        assertThat(permit.allowed()).isTrue();
        assertThat(count()).isEqualTo(1);
        assertThat(new SecretAiCallBudget(jdbc, transactions)
                .acquire("CLAUDE", "claude-sonnet-5-5", "GUIDE", TIMEOUT).reasonCode()).isEqualTo("REQUEST_IN_PROGRESS");
        permit.close();
        assertThat(count()).isEqualTo(1);
    }

    @Test
    void concurrentCallersAcquireExactlyOneDispatchSlot() throws Exception {
        try (var workers = Executors.newFixedThreadPool(4)) {
            var start = new CountDownLatch(1);
            var pending = new ArrayList<java.util.concurrent.Future<SecretAiCallBudget.Permit>>();
            for (int worker = 0; worker < 4; worker++) {
                var replica = new SecretAiCallBudget(jdbc, transactions);
                pending.add(workers.submit(() -> {
                    start.await();
                    return replica.acquire("CLAUDE", "claude-sonnet-5-5", "GUIDE", TIMEOUT);
                }));
            }
            start.countDown();
            var permits = new ArrayList<SecretAiCallBudget.Permit>();
            try {
                for (var result : pending) permits.add(result.get(10, TimeUnit.SECONDS));
                assertThat(permits).filteredOn(SecretAiCallBudget.Permit::allowed).hasSize(1);
                assertThat(permits).filteredOn(permit -> !permit.allowed())
                        .allSatisfy(permit -> assertThat(permit.reasonCode()).isEqualTo("REQUEST_IN_PROGRESS"));
                assertThat(count()).isEqualTo(1);
            } finally {
                permits.forEach(SecretAiCallBudget.Permit::close);
            }
        }
    }

    @Test
    void anUnavailableLedgerOrInvalidRegistrationRejectsBeforeDispatch() {
        for (String provider : List.of("CLAUDE", "UNREGISTERED")) {
            assertThat(first.acquire(provider, "unknown-model", "GUIDE", TIMEOUT).reasonCode())
                    .isEqualTo("CONFIGURATION_INVALID");
        }
        assertThat(first.acquire(null, null, null, null).allowed()).isFalse();
        assertThat(count()).isZero();
        jdbc.execute("ALTER TABLE secret_ai_call_ledger RENAME TO unavailable_ai_budget");
        try {
            assertThat(first.acquire("CLAUDE", "claude-sonnet-5-5", "GUIDE", TIMEOUT).reasonCode())
                    .isEqualTo("CALL_BUDGET_UNAVAILABLE");
        } finally {
            jdbc.execute("ALTER TABLE unavailable_ai_budget RENAME TO secret_ai_call_ledger");
        }
        assertThat(count()).isZero();
    }

    @Test
    void theLedgerContainsOnlyBoundedOperationalMetadata() {
        assertThat(jdbc.queryForList("""
                SELECT column_name FROM information_schema.columns
                WHERE table_schema='public' AND table_name='secret_ai_call_ledger' ORDER BY ordinal_position
                """, String.class)).containsExactly("call_id", "provider", "model", "purpose", "state",
                "reserved_at", "deadline_at", "completed_at");
        try (var permit = first.acquire("CLAUDE", "claude-sonnet-5-5", "GUIDE", TIMEOUT)) {
            assertThat(permit.allowed()).isTrue();
            assertThat(jdbc.queryForObject("SELECT deadline_at-reserved_at=interval '60 seconds' FROM secret_ai_call_ledger", Boolean.class)).isTrue();
        }
    }

    private long count() {
        return jdbc.queryForObject("SELECT count(*) FROM secret_ai_call_ledger", Long.class);
    }
}
