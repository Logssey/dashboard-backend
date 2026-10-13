package com.logssey.secretworker;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecretScheduleServiceTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static JdbcTemplate jdbc;
    private static DataSourceTransactionManager transactions;
    private SecretScheduleService service;

    @BeforeAll
    static void startDatabase() {
        POSTGRES.start();
        var datasource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(datasource).load().migrate();
        jdbc = new JdbcTemplate(datasource);
        transactions = new DataSourceTransactionManager(datasource);
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @BeforeEach
    void resetSchedules() {
        jdbc.execute("TRUNCATE secret_connections RESTART IDENTITY CASCADE");
        service = newService(true, 100);
    }

    @Test
    void reservesPendingJobAndScopeSnapshotWithoutPretendingCollectionSucceeded() {
        var due = pastDue();
        long connectionId = connection("ACTIVE", due, true);
        var previousSuccess = due.minusDays(1);
        jdbc.update("UPDATE secret_connections SET last_collection_success_at = ? WHERE connection_id = ?", previousSuccess, connectionId);

        assertThat(service.reserveDueJobs()).isEqualTo(1);
        assertThat(count("secret_jobs")).isEqualTo(1);
        assertThat(count("secret_scan_runs")).isEqualTo(1);
        assertThat(count("secret_run_scopes")).isEqualTo(1);
        assertThat(jdbc.queryForMap("SELECT status, attempt_no, lease_owner, lease_until, finished_at FROM secret_jobs"))
                .containsEntry("status", "PENDING").containsEntry("attempt_no", 0)
                .containsEntry("lease_owner", null).containsEntry("lease_until", null).containsEntry("finished_at", null);
        assertThat(jdbc.queryForMap("""
                SELECT collection_status, detection_status, validation_status, result_status, started_at, finished_at
                FROM secret_scan_runs
                """))
                .containsEntry("collection_status", "PENDING").containsEntry("detection_status", "PENDING")
                .containsEntry("validation_status", "PENDING").containsEntry("result_status", "PENDING")
                .containsEntry("started_at", null).containsEntry("finished_at", null);
        assertThat(timestamp("SELECT scheduled_at FROM secret_jobs")).isEqualTo(due);
        assertThat(nextDue(connectionId)).isEqualTo(due.plusHours(6));
        assertThat(timestamp("SELECT last_collection_success_at FROM secret_connections")).isEqualTo(previousSuccess);
        assertThat(jdbc.queryForObject("SELECT object_count FROM secret_run_scopes", Long.class)).isNull();
    }

    @Test
    void ignoresPausedErroredFutureUnscheduledAndUnapprovedConnections() {
        connection("PAUSED", pastDue(), true);
        connection("ERROR", pastDue(), true);
        connection("ACTIVE", pastDue().plusDays(1), true);
        connection("ACTIVE", null, true);
        long disabledScope = connection("ACTIVE", pastDue(), true);
        jdbc.update("UPDATE secret_connection_scopes SET enabled = false WHERE connection_id = ?", disabledScope);
        connection("ACTIVE", pastDue(), false);

        assertThat(service.reserveDueJobs()).isZero();
        assertThat(count("secret_jobs")).isZero();
    }

    @Test
    void repeatedPollAndNewServiceInstanceKeepOneReservationAndPersistedNextDue() {
        long id = connection("ACTIVE", pastDue(), true);
        assertThat(service.reserveDueJobs()).isEqualTo(1);
        var due = nextDue(id);

        assertThat(service.reserveDueJobs()).isZero();
        assertThat(newService(true, 100).reserveDueJobs()).isZero();
        assertThat(count("secret_jobs")).isEqualTo(1);
        assertThat(nextDue(id)).isEqualTo(due);
    }

    @Test
    void outstandingOverdueJobPreventsAnUnboundedQueueAndPreservesOverdueTimestamp() {
        long id = connection("ACTIVE", pastDue().minusHours(12), true);
        assertThat(service.reserveDueJobs()).isEqualTo(1);
        var due = nextDue(id);

        assertThat(service.reserveDueJobs()).isZero();
        assertThat(count("secret_jobs")).isEqualTo(1);
        assertThat(nextDue(id)).isEqualTo(due);
        assertThat(due).isBefore(OffsetDateTime.now());
    }

    @Test
    void nextReservationUsesPriorDueTimeEvenAfterFailureRatherThanCompletionTime() {
        var firstDue = pastDue().minusHours(12);
        long id = connection("ACTIVE", firstDue, true);
        assertThat(service.reserveDueJobs()).isEqualTo(1);
        jdbc.update("UPDATE secret_jobs SET status = 'FAILED', finished_at = CURRENT_TIMESTAMP, last_error_code = 'TEST_ONLY'");

        assertThat(newService(true, 100).reserveDueJobs()).isEqualTo(1);
        assertThat(jdbc.queryForList("SELECT scheduled_at FROM secret_jobs ORDER BY job_id", OffsetDateTime.class))
                .containsExactly(firstDue, firstDue.plusHours(6));
        assertThat(nextDue(id)).isEqualTo(firstDue.plusHours(12));
        assertThat(jdbc.queryForObject("SELECT last_collection_success_at FROM secret_connections", OffsetDateTime.class)).isNull();
    }

    @Test
    void disabledSchedulerDoesNotChangeDatabase() {
        var due = pastDue();
        long id = connection("ACTIVE", due, true);

        assertThat(newService(false, 100).reserveDueJobs()).isZero();
        assertThat(count("secret_jobs")).isZero();
        assertThat(nextDue(id)).isEqualTo(due);
    }

    @Test
    void boundedBatchEventuallyReservesAllDueConnections() {
        var due = pastDue();
        connection("ACTIVE", due, true);
        connection("ACTIVE", due, true);
        connection("ACTIVE", due, true);
        var bounded = newService(true, 2);

        assertThat(bounded.reserveDueJobs()).isEqualTo(2);
        assertThat(bounded.reserveDueJobs()).isEqualTo(1);
        assertThat(bounded.reserveDueJobs()).isZero();
        assertThat(count("secret_jobs")).isEqualTo(3);
    }

    @Test
    void concurrentWorkersReserveEachConnectionOnlyOnce() throws Exception {
        connection("ACTIVE", pastDue(), true);
        connection("ACTIVE", pastDue(), true);
        var barrier = new CyclicBarrier(8);
        try (var executor = Executors.newFixedThreadPool(8)) {
            var results = new ArrayList<Future<Integer>>();
            for (int i = 0; i < 8; i++) {
                results.add(executor.submit(() -> {
                    barrier.await(10, TimeUnit.SECONDS);
                    return newService(true, 100).reserveDueJobs();
                }));
            }
            int total = 0;
            for (var result : results) {
                total += result.get(10, TimeUnit.SECONDS);
            }
            assertThat(total).isEqualTo(2);
        }
        assertThat(count("secret_jobs")).isEqualTo(2);
        assertThat(count("secret_scan_runs")).isEqualTo(2);
        assertThat(count("secret_run_scopes")).isEqualTo(2);
    }

    @Test
    void skipsConnectionLockedByAnotherWorkerWithoutBlockingOtherConnections() throws Exception {
        long lockedId = connection("ACTIVE", pastDue(), true);
        connection("ACTIVE", pastDue(), true);
        var locked = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var lockHolder = executor.submit(() -> new TransactionTemplate(transactions).execute(status -> {
                jdbc.queryForObject("SELECT connection_id FROM secret_connections WHERE connection_id = ? FOR UPDATE", Long.class, lockedId);
                locked.countDown();
                try {
                    if (!release.await(10, TimeUnit.SECONDS)) {
                        throw new IllegalStateException("Lock test timed out");
                    }
                } catch (InterruptedException error) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(error);
                }
                return null;
            }));
            try {
                assertThat(locked.await(5, TimeUnit.SECONDS)).isTrue();
                assertThat(executor.submit(service::reserveDueJobs).get(3, TimeUnit.SECONDS)).isEqualTo(1);
            } finally {
                release.countDown();
            }
            lockHolder.get(5, TimeUnit.SECONDS);
        }
        assertThat(service.reserveDueJobs()).isEqualTo(1);
        assertThat(count("secret_jobs")).isEqualTo(2);
    }

    @Test
    void failureRollsBackJobRunScopesAndNextDueTogether() {
        var due = pastDue();
        long id = connection("ACTIVE", due, true);
        var failingRepository = new SecretScheduleRepository(jdbc) {
            @Override
            public void reserve(DueConnection connection, OffsetDateTime now, SecretSchedulerProperties properties) {
                super.reserve(connection, now, properties);
                throw new IllegalStateException("Injected transaction failure");
            }
        };
        var failing = new SecretScheduleService(failingRepository, properties(true, 100), transactions);

        assertThatThrownBy(failing::reserveDueJobs).isInstanceOf(IllegalStateException.class);
        assertThat(count("secret_jobs")).isZero();
        assertThat(count("secret_scan_runs")).isZero();
        assertThat(count("secret_run_scopes")).isZero();
        assertThat(nextDue(id)).isEqualTo(due);
        assertThat(service.reserveDueJobs()).isEqualTo(1);
    }

    @Test
    void scopeRevisionAndVersionAreFrozenForReservedRun() {
        long id = connection("ACTIVE", pastDue(), true);
        long originalScope = jdbc.queryForObject("SELECT scope_id FROM secret_connection_scopes", Long.class);
        assertThat(service.reserveDueJobs()).isEqualTo(1);
        jdbc.update("UPDATE secret_connection_scopes SET enabled = false WHERE scope_id = ?", originalScope);
        jdbc.update("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref, history_limit, enabled)
                VALUES (?, 'fixture-scope', 2, 'GITHUB_REPOSITORY_FILES', 'test-reference-v2', 'CURRENT_COMMIT_ONLY', true)
                """, id);
        jdbc.update("UPDATE secret_connections SET scope_version = 2 WHERE connection_id = ?", id);

        assertThat(jdbc.queryForObject("SELECT scope_version FROM secret_scan_runs", Long.class)).isEqualTo(1L);
        assertThat(jdbc.queryForObject("SELECT scope_id FROM secret_run_scopes", Long.class)).isEqualTo(originalScope);
    }

    @Test
    void workerStartsWithoutApiAuthenticationConfigurationAndDefaultsToNoPolling() {
        try (var context = new SpringApplicationBuilder(SecretWorkerApplication.class).run(
                "--spring.config.import=", "--spring.datasource.url=" + POSTGRES.getJdbcUrl(),
                "--spring.datasource.username=" + POSTGRES.getUsername(),
                "--spring.datasource.password=" + POSTGRES.getPassword(),
                "--spring.main.keep-alive=false", "--debug=false")) {
            assertThat(context.getBeansOfType(SecretSchedulePoller.class)).isEmpty();
            assertThat(context.getBean(SecretSchedulerProperties.class).scanInterval()).isEqualTo(Duration.ofHours(6));
            assertThat(context.getBean(SecretScheduleService.class).reserveDueJobs()).isZero();
        }
    }

    private SecretScheduleService newService(boolean enabled, int batchSize) {
        return new SecretScheduleService(new SecretScheduleRepository(jdbc), properties(enabled, batchSize), transactions);
    }

    private SecretSchedulerProperties properties(boolean enabled, int batchSize) {
        return new SecretSchedulerProperties(enabled, Duration.ofSeconds(30), Duration.ofHours(6), batchSize, 3);
    }

    private long connection(String status, OffsetDateTime due, boolean addScope) {
        long id = jdbc.queryForObject("""
                INSERT INTO secret_connections (provider, display_name, auth_ref, status, scope_version, next_due_at)
                VALUES ('GITHUB', 'Synthetic schedule', 'test-only-reference', ?, 1, ?) RETURNING connection_id
                """, Long.class, status, due);
        if (addScope) {
            jdbc.update("""
                    INSERT INTO secret_connection_scopes
                        (connection_id, scope_key, revision, content_type, approved_ref, history_limit, enabled)
                    VALUES (?, 'fixture-scope', 1, 'GITHUB_REPOSITORY_FILES', 'test-reference', 'CURRENT_COMMIT_ONLY', true)
                    """, id);
        }
        return id;
    }

    private OffsetDateTime pastDue() {
        return OffsetDateTime.now(java.time.ZoneOffset.UTC).minusMinutes(1).truncatedTo(ChronoUnit.MICROS);
    }

    private OffsetDateTime nextDue(long id) {
        return jdbc.queryForObject("SELECT next_due_at FROM secret_connections WHERE connection_id = ?", OffsetDateTime.class, id);
    }

    private OffsetDateTime timestamp(String sql) {
        return jdbc.queryForObject(sql, OffsetDateTime.class);
    }

    private long count(String table) {
        return jdbc.queryForObject("SELECT COUNT(*) FROM " + table, Long.class);
    }
}
