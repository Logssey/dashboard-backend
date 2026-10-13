package com.logssey.secretworker;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(OutputCaptureExtension.class)
class SecretJobExecutionServiceTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static JdbcTemplate jdbc;
    private static DataSourceTransactionManager transactions;
    private SecretJobExecutionService service;

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
    void resetJobs() {
        jdbc.execute("TRUNCATE secret_connections RESTART IDENTITY CASCADE");
        service = newService();
    }

    @Test
    void concurrentWorkersClaimEachPendingJobOnlyOnce() throws Exception {
        scheduledJob(1);
        scheduledJob(1);
        var barrier = new CyclicBarrier(6);
        List<ClaimedSecretJob> all = new ArrayList<>();
        try (var executor = Executors.newFixedThreadPool(6)) {
            List<Future<java.util.Optional<ClaimedSecretJob>>> calls = new ArrayList<>();
            for (int i = 0; i < 6; i++) {
                calls.add(executor.submit(() -> {
                    barrier.await(10, TimeUnit.SECONDS);
                    return newService().claimNextJob();
                }));
            }
            for (var call : calls) {
                call.get(10, TimeUnit.SECONDS).ifPresent(all::add);
            }
        }
        assertThat(all).hasSize(2).extracting(ClaimedSecretJob::jobId).doesNotHaveDuplicates();
        assertThat(all).allSatisfy(job -> assertThat(job.attemptNo()).isEqualTo(1));
        assertThat(service.claimNextJob()).isEmpty();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_jobs WHERE status = 'LEASED'", Long.class))
                .isEqualTo(2L);
    }

    @Test
    void expiredLeaseRetriesSameRunWithBackoffAndFencesOldOwner() {
        long jobId = scheduledJob(1);
        var first = onlyClaim();
        assertThat(first.jobId()).isEqualTo(jobId);
        jdbc.update("UPDATE secret_scan_runs SET collection_status = 'RUNNING' WHERE run_id = ?", first.runId());
        jdbc.update("UPDATE secret_run_scopes SET collection_status = 'RUNNING' WHERE run_id = ?", first.runId());
        jdbc.update("UPDATE secret_jobs SET lease_until = clock_timestamp() - INTERVAL '1 second' WHERE job_id = ?", jobId);

        assertThat(service.renewLease(jobId, first.leaseToken())).isFalse();
        assertThat(service.persistIfLeased(jobId, first.leaseToken(), () ->
                jdbc.update("UPDATE secret_scan_runs SET collection_status = 'SUCCEEDED' WHERE run_id = ?", first.runId())))
                .isFalse();
        assertThat(service.complete(jobId, first.leaseToken())).isFalse();
        assertThat(service.recoverExpiredJobs()).isEqualTo(1);
        assertThat(service.recoverExpiredJobs()).isZero();
        assertThat(jdbc.queryForObject("SELECT status FROM secret_jobs WHERE job_id = ?", String.class, jobId))
                .isEqualTo("PENDING");
        assertThat(jdbc.queryForObject("SELECT last_error_code FROM secret_jobs WHERE job_id = ?", String.class, jobId))
                .isEqualTo("LEASE_EXPIRED");
        assertThat(jdbc.queryForObject("SELECT collection_status FROM secret_scan_runs WHERE run_id = ?",
                String.class, first.runId())).isEqualTo("PENDING");
        assertThat(jdbc.queryForObject("SELECT collection_status FROM secret_run_scopes WHERE run_id = ?",
                String.class, first.runId())).isEqualTo("PENDING");
        assertThat(jdbc.queryForObject("SELECT available_at > clock_timestamp() FROM secret_jobs WHERE job_id = ?",
                Boolean.class, jobId)).isTrue();
        assertThat(service.claimNextJob()).isEmpty();

        jdbc.update("UPDATE secret_jobs SET available_at = clock_timestamp() - INTERVAL '1 second' WHERE job_id = ?", jobId);
        var second = onlyClaim();
        assertThat(second.runId()).isEqualTo(first.runId());
        assertThat(second.attemptNo()).isEqualTo(2);
        assertThat(second.leaseToken()).isNotEqualTo(first.leaseToken());
        assertThat(service.renewLease(jobId, first.leaseToken())).isFalse();
        assertThat(service.fail(jobId, first.leaseToken(), SecretJobFailureCode.SOURCE_UNAVAILABLE, false)).isFalse();
        assertThat(service.renewLease(jobId, second.leaseToken())).isTrue();
    }

    @Test
    void retriesStopAtMaxAttemptsAndNeverReportUnfinishedCollectionAsSuccess() {
        long jobId = scheduledJob(1);
        for (int attempt = 1; attempt <= 3; attempt++) {
            var claimed = onlyClaim();
            assertThat(claimed.attemptNo()).isEqualTo(attempt);
            assertThat(service.persistIfLeased(jobId, claimed.leaseToken(), () -> {
                jdbc.update("UPDATE secret_scan_runs SET collection_status = 'RUNNING' WHERE run_id = ?", claimed.runId());
                jdbc.update("UPDATE secret_run_scopes SET collection_status = 'RUNNING' WHERE run_id = ?", claimed.runId());
            })).isTrue();
            assertThat(service.fail(jobId, claimed.leaseToken(), SecretJobFailureCode.SOURCE_UNAVAILABLE, true)).isTrue();
            if (attempt < 3) {
                assertThat(jdbc.queryForObject("SELECT status FROM secret_jobs WHERE job_id = ?", String.class, jobId))
                        .isEqualTo("PENDING");
                jdbc.update("UPDATE secret_jobs SET available_at = clock_timestamp() - INTERVAL '1 second' WHERE job_id = ?", jobId);
            }
        }
        assertThat(jdbc.queryForMap("SELECT status, attempt_no, last_error_code, lease_owner, lease_until FROM secret_jobs"))
                .containsEntry("status", "FAILED").containsEntry("attempt_no", 3)
                .containsEntry("last_error_code", "SOURCE_UNAVAILABLE")
                .containsEntry("lease_owner", null).containsEntry("lease_until", null);
        assertThat(jdbc.queryForMap("SELECT result_status, collection_status, detection_status FROM secret_scan_runs"))
                .containsEntry("result_status", "FAILED").containsEntry("collection_status", "FAILED")
                .containsEntry("detection_status", "SKIPPED");
        assertThat(jdbc.queryForObject("SELECT last_collection_success_at FROM secret_connections",
                OffsetDateTime.class)).isNull();
        assertThat(service.claimNextJob()).isEmpty();
    }

    @Test
    void completedZeroObjectScanRequiresTerminalStagesAndScopes() {
        long jobId = scheduledJob(1);
        var claim = onlyClaim();
        assertThat(service.complete(jobId, claim.leaseToken())).isFalse();
        assertThat(jdbc.queryForObject("SELECT result_status FROM secret_scan_runs", String.class)).isEqualTo("RUNNING");
        assertThat(service.persistIfLeased(jobId, claim.leaseToken(), () -> {
            jdbc.update("""
                    UPDATE secret_run_scopes SET collection_status = 'SUCCEEDED', object_count = 0,
                                                 finished_at = clock_timestamp() WHERE run_id = ?
                    """, claim.runId());
            jdbc.update("""
                    UPDATE secret_scan_runs SET collection_status = 'SUCCEEDED', detection_status = 'SKIPPED',
                                                validation_status = 'SKIPPED' WHERE run_id = ?
                    """, claim.runId());
        })).isTrue();
        assertThat(service.complete(jobId, claim.leaseToken())).isTrue();
        assertThat(service.complete(jobId, claim.leaseToken())).isFalse();
        assertThat(jdbc.queryForObject("SELECT result_status FROM secret_scan_runs", String.class))
                .isEqualTo("SUCCEEDED");
        assertThat(jdbc.queryForObject("SELECT status FROM secret_jobs", String.class)).isEqualTo("SUCCEEDED");
        assertThat(jdbc.queryForObject("SELECT last_collection_success_at FROM secret_connections",
                OffsetDateTime.class)).isEqualTo(jdbc.queryForObject(
                "SELECT finished_at FROM secret_run_scopes", OffsetDateTime.class));
    }

    @Test
    void unknownObjectCountOrSkippedDetectionWithObjectsCannotLookLikeSuccess() {
        scheduledJob(1);
        var claim = onlyClaim();
        jdbc.update("UPDATE secret_run_scopes SET collection_status = 'SUCCEEDED' WHERE run_id = ?", claim.runId());
        jdbc.update("""
                UPDATE secret_scan_runs SET collection_status = 'SUCCEEDED', detection_status = 'SKIPPED',
                                            validation_status = 'SKIPPED' WHERE run_id = ?
                """, claim.runId());
        assertThat(service.complete(claim.jobId(), claim.leaseToken())).isFalse();
        jdbc.update("UPDATE secret_run_scopes SET object_count = 1 WHERE run_id = ?", claim.runId());
        assertThat(service.complete(claim.jobId(), claim.leaseToken())).isFalse();
        jdbc.update("UPDATE secret_scan_runs SET detection_status = 'SUCCEEDED' WHERE run_id = ?", claim.runId());
        assertThat(service.complete(claim.jobId(), claim.leaseToken())).isFalse();
        assertThat(service.fail(claim.jobId(), claim.leaseToken(),
                SecretJobFailureCode.DETECTOR_TEMPORARY, true)).isTrue();
        assertThat(jdbc.queryForObject("SELECT last_collection_success_at FROM secret_connections",
                OffsetDateTime.class)).isNull();
        jdbc.update("UPDATE secret_jobs SET available_at = clock_timestamp() - INTERVAL '1 second'");
        var retry = onlyClaim();
        assertThat(retry.runId()).isEqualTo(claim.runId());
        jdbc.update("UPDATE secret_run_scopes SET finished_at = clock_timestamp() WHERE run_id = ?", retry.runId());
        assertThat(service.complete(retry.jobId(), retry.leaseToken())).isTrue();
    }

    @Test
    void failedScopeIsPartialCoverageRatherThanAZeroObjectSuccess() {
        scheduledJob(2);
        var claim = onlyClaim();
        jdbc.update("""
                UPDATE secret_run_scopes
                SET collection_status = CASE WHEN scope_id = (SELECT MIN(scope_id) FROM secret_run_scopes)
                                             THEN 'SUCCEEDED' ELSE 'FAILED' END,
                    object_count = CASE WHEN scope_id = (SELECT MIN(scope_id) FROM secret_run_scopes)
                                        THEN 0 ELSE NULL END,
                    failure_code = CASE WHEN scope_id = (SELECT MIN(scope_id) FROM secret_run_scopes)
                                        THEN NULL ELSE 'ACCESS_DENIED' END,
                    finished_at = clock_timestamp()
                WHERE run_id = ?
                """, claim.runId());
        jdbc.update("""
                UPDATE secret_scan_runs SET collection_status = 'SUCCEEDED', detection_status = 'SUCCEEDED',
                                            validation_status = 'SKIPPED' WHERE run_id = ?
                """, claim.runId());
        assertThat(service.complete(claim.jobId(), claim.leaseToken())).isFalse();
        jdbc.update("UPDATE secret_scan_runs SET collection_status = 'PARTIAL' WHERE run_id = ?", claim.runId());
        assertThat(service.complete(claim.jobId(), claim.leaseToken())).isTrue();
        assertThat(jdbc.queryForObject("SELECT result_status FROM secret_scan_runs", String.class))
                .isEqualTo("PARTIAL");
        assertThat(jdbc.queryForObject("SELECT last_collection_success_at FROM secret_connections",
                OffsetDateTime.class)).isNull();
        assertThat(jdbc.queryForList("SELECT object_count FROM secret_run_scopes ORDER BY scope_id", Long.class))
                .containsExactly(0L, null);
    }

    @Test
    void successfulCollectionSurvivesDetectionRetryWithoutForgingWholeRunSuccess() {
        long jobId = scheduledJob(1);
        var first = onlyClaim();
        var collectionCompletedAt = OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(20)
                .truncatedTo(ChronoUnit.MICROS);
        jdbc.update("""
                UPDATE secret_run_scopes SET collection_status = 'SUCCEEDED', object_count = 0,
                                             finished_at = ? WHERE run_id = ?
                """, collectionCompletedAt, first.runId());
        jdbc.update("UPDATE secret_scan_runs SET collection_status = 'SUCCEEDED', detection_status = 'RUNNING' WHERE run_id = ?",
                first.runId());
        assertThat(service.fail(jobId, first.leaseToken(), SecretJobFailureCode.DETECTOR_TEMPORARY, true)).isTrue();
        assertThat(jdbc.queryForMap("SELECT collection_status, detection_status, result_status FROM secret_scan_runs"))
                .containsEntry("collection_status", "SUCCEEDED").containsEntry("detection_status", "PENDING")
                .containsEntry("result_status", "PENDING");
        assertThat(jdbc.queryForObject("SELECT last_collection_success_at FROM secret_connections",
                OffsetDateTime.class)).isEqualTo(collectionCompletedAt);
        jdbc.update("UPDATE secret_jobs SET available_at = clock_timestamp() - INTERVAL '1 second' WHERE job_id = ?", jobId);
        var second = onlyClaim();
        assertThat(second.runId()).isEqualTo(first.runId());
        assertThat(service.complete(jobId, second.leaseToken())).isFalse();
        jdbc.update("UPDATE secret_scan_runs SET detection_status = 'SUCCEEDED', validation_status = 'SKIPPED' WHERE run_id = ?",
                second.runId());
        assertThat(service.complete(jobId, second.leaseToken())).isTrue();
        assertThat(jdbc.queryForObject("SELECT last_collection_success_at FROM secret_connections",
                OffsetDateTime.class)).isEqualTo(collectionCompletedAt);
    }

    @Test
    void permanentLaterStageFailureKeepsLatestActualCollectionCompletionTime() {
        scheduledJob(2);
        var claim = onlyClaim();
        var firstScopeFinishedAt = OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(30)
                .truncatedTo(ChronoUnit.MICROS);
        var lastScopeFinishedAt = firstScopeFinishedAt.plusMinutes(3);
        jdbc.update("""
                UPDATE secret_run_scopes
                SET collection_status = 'SUCCEEDED', object_count = 0,
                    finished_at = CASE WHEN scope_id = (SELECT MIN(scope_id) FROM secret_run_scopes)
                                       THEN ? ELSE ? END
                WHERE run_id = ?
                """, firstScopeFinishedAt, lastScopeFinishedAt, claim.runId());
        jdbc.update("""
                UPDATE secret_scan_runs SET collection_status = 'SUCCEEDED', detection_status = 'RUNNING'
                WHERE run_id = ?
                """, claim.runId());
        assertThat(service.fail(claim.jobId(), claim.leaseToken(),
                SecretJobFailureCode.DETECTOR_TEMPORARY, false)).isTrue();
        assertThat(jdbc.queryForObject("SELECT result_status FROM secret_scan_runs", String.class))
                .isEqualTo("FAILED");
        assertThat(jdbc.queryForObject("SELECT last_collection_success_at FROM secret_connections",
                OffsetDateTime.class)).isEqualTo(lastScopeFinishedAt);
    }

    @Test
    void pausedConnectionIsNotClaimedAndMissingCodesNeverReachDatabase() {
        long jobId = scheduledJob(1);
        jdbc.update("UPDATE secret_connections SET status = 'PAUSED'");
        assertThat(service.claimNextJob()).isEmpty();
        jdbc.update("UPDATE secret_connections SET status = 'ACTIVE'");
        var claim = onlyClaim();
        assertThatThrownBy(() -> service.fail(jobId, claim.leaseToken(), null, false))
                .isInstanceOf(NullPointerException.class);
        assertThat(jdbc.queryForObject("SELECT last_error_code FROM secret_jobs", String.class)).isNull();
    }

    @Test
    void enablingPollerWithoutProcessorLeavesPendingJobsUntouched() {
        scheduledJob(1);
        var factory = new StaticListableBeanFactory();
        new SecretJobPoller(service, executionProperties(),
                factory.getBeanProvider(SecretJobProcessor.class)).poll();
        assertThat(jdbc.queryForMap("SELECT status, attempt_no, lease_owner FROM secret_jobs"))
                .containsEntry("status", "PENDING").containsEntry("attempt_no", 0)
                .containsEntry("lease_owner", null);
    }

    @Test
    void fencedPersistenceRollsBackAndProcessorExceptionDoesNotExposeItsMessage(CapturedOutput output) {
        long jobId = scheduledJob(1);
        var factory = new StaticListableBeanFactory();
        String syntheticSecretMarker = "synthetic-raw-secret-do-not-log";
        factory.addBean("processor", (SecretJobProcessor) (job, execution) -> {
            throw new IllegalStateException(syntheticSecretMarker);
        });
        var poller = new SecretJobPoller(service, executionProperties(),
                factory.getBeanProvider(SecretJobProcessor.class));
        poller.poll();
        assertThat(jdbc.queryForMap("SELECT status, last_error_code FROM secret_jobs"))
                .containsEntry("status", "PENDING").containsEntry("last_error_code", "PROCESSOR_FAILURE");
        assertThat(jdbc.queryForObject("SELECT failure_code FROM secret_scan_runs", String.class))
                .isEqualTo("PROCESSOR_FAILURE");
        assertThat(output.getAll()).doesNotContain(syntheticSecretMarker);
        assertThat(jdbc.queryForObject("""
                SELECT COALESCE(string_agg(last_error_code, ''), '') FROM secret_jobs
                """, String.class)).doesNotContain(syntheticSecretMarker);

        jdbc.update("UPDATE secret_jobs SET available_at = clock_timestamp() - INTERVAL '1 second' WHERE job_id = ?", jobId);
        var second = onlyClaim();
        assertThatThrownBy(() -> service.persistIfLeased(jobId, second.leaseToken(), () -> {
            jdbc.update("UPDATE secret_scan_runs SET collection_status = 'RUNNING' WHERE run_id = ?", second.runId());
            throw new IllegalStateException("rollback without logging the message");
        })).isInstanceOf(IllegalStateException.class);
        assertThat(jdbc.queryForObject("SELECT collection_status FROM secret_scan_runs", String.class))
                .isEqualTo("PENDING");
    }

    private SecretJobExecutionService newService() {
        return new SecretJobExecutionService(new SecretJobRepository(jdbc),
                executionProperties(), transactions);
    }

    private SecretJobProperties executionProperties() {
        return new SecretJobProperties(false, Duration.ofSeconds(30), Duration.ofMinutes(5), 10,
                Duration.ofSeconds(2), Duration.ofSeconds(8));
    }

    private ClaimedSecretJob onlyClaim() {
        var job = service.claimNextJob();
        assertThat(job).isPresent();
        return job.orElseThrow();
    }

    @Test
    void providerSpecificProcessorDoesNotClaimAnotherProvidersJob() {
        scheduledJob(1);
        assertThat(service.claimNextJob("AWS")).isEmpty();
        assertThat(service.claimNextJob("GITHUB")).isPresent();
    }

    private long scheduledJob(int scopeCount) {
        var connectionId = jdbc.queryForObject("""
                INSERT INTO secret_connections (provider, display_name, auth_ref, status, scope_version, next_due_at)
                VALUES ('GITHUB', 'Synthetic schedule', 'test-only-reference', 'ACTIVE', 1,
                        clock_timestamp() - INTERVAL '1 minute') RETURNING connection_id
                """, Long.class);
        for (int scope = 1; scope <= scopeCount; scope++) {
            jdbc.update("""
                    INSERT INTO secret_connection_scopes
                        (connection_id, scope_key, revision, content_type, approved_ref, enabled)
                    VALUES (?, ?, 1, 'GITHUB_REPOSITORY_FILES', 'test-reference', true)
                    """, connectionId, "fixture-scope-" + scope);
        }
        var schedule = new SecretScheduleService(new SecretScheduleRepository(jdbc),
                new SecretSchedulerProperties(true, Duration.ofSeconds(30), Duration.ofHours(6), 10, 3),
                transactions);
        assertThat(schedule.reserveDueJobs()).isEqualTo(1);
        return jdbc.queryForObject("SELECT job_id FROM secret_jobs WHERE connection_id = ?", Long.class, connectionId);
    }
}
