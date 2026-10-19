package com.logssey.iacworker;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
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

/** ERD "구현 검증": 큐를 동시에 선점하면 한 워커만 가져감, 남은 plan 행 정리. */
@ExtendWith(OutputCaptureExtension.class)
class IacJobExecutionServiceTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static JdbcTemplate jdbc;
    private static DataSourceTransactionManager transactions;
    private IacJobExecutionService service;

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
    void reset() {
        jdbc.execute("TRUNCATE iac_jobs, iac_runs, iac_repos RESTART IDENTITY CASCADE");
        service = newService();
    }

    @Test
    void concurrentWorkersClaimEachPendingJobOnlyOnce() throws Exception {
        job("ENRICH_GRAPH", null);
        job("ENRICH_GRAPH", null);
        var barrier = new CyclicBarrier(6);
        List<ClaimedIacJob> all = new ArrayList<>();
        try (var executor = Executors.newFixedThreadPool(6)) {
            List<Future<Optional<ClaimedIacJob>>> calls = new ArrayList<>();
            for (int i = 0; i < 6; i++) {
                calls.add(executor.submit(() -> {
                    barrier.await(10, TimeUnit.SECONDS);
                    return newService().claimNextJob(IacJobKind.ENRICH_GRAPH);
                }));
            }
            for (var call : calls) {
                call.get(10, TimeUnit.SECONDS).ifPresent(all::add);
            }
        }
        assertThat(all).hasSize(2).extracting(ClaimedIacJob::jobId).doesNotHaveDuplicates();
        assertThat(all).allSatisfy(job -> assertThat(job.attemptNo()).isEqualTo(1));
        assertThat(service.claimNextJob(IacJobKind.ENRICH_GRAPH)).isEmpty();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_jobs WHERE status = 'LEASED'", Long.class))
                .isEqualTo(2L);
    }

    @Test
    void claimsOnlyTheRequestedKindAndNeverTheCronJobRecord() {
        long run = run();
        long analyze = job("ANALYZE_RUN", run);
        job("COLLECT_GRAPH", null);

        assertThat(service.claimNextJob(IacJobKind.ENRICH_GRAPH)).isEmpty();
        var claimed = service.claimNextJob(IacJobKind.ANALYZE_RUN).orElseThrow();
        assertThat(claimed.jobId()).isEqualTo(analyze);
        assertThat(claimed.runId()).isEqualTo(run);
        for (IacJobKind kind : IacJobKind.values()) {
            assertThat(service.claimNextJob(kind)).isEmpty();
        }
        assertThat(jdbc.queryForObject("SELECT status FROM iac_jobs WHERE kind = 'COLLECT_GRAPH'", String.class))
                .isEqualTo("PENDING");
    }

    @Test
    void expiredLeaseRetriesWithBackoffAndFencesTheOldOwner() {
        long jobId = job("ENRICH_GRAPH", null);
        var first = service.claimNextJob(IacJobKind.ENRICH_GRAPH).orElseThrow();
        jdbc.update("UPDATE iac_jobs SET lease_until = clock_timestamp() - INTERVAL '1 second' WHERE job_id = ?", jobId);

        assertThat(service.renewLease(jobId, first.leaseToken())).isFalse();
        assertThat(service.persistIfLeased(jobId, first.leaseToken(), () ->
                jdbc.update("UPDATE iac_jobs SET stats = '{\"written\":true}' WHERE job_id = ?", jobId))).isFalse();
        assertThat(service.complete(jobId, first.leaseToken())).isFalse();
        assertThat(service.recoverExpiredJobs()).isEqualTo(1);
        assertThat(service.recoverExpiredJobs()).isZero();
        assertThat(jdbc.queryForObject("SELECT status || '/' || last_error_code FROM iac_jobs WHERE job_id = ?",
                String.class, jobId)).isEqualTo("PENDING/LEASE_EXPIRED");
        assertThat(jdbc.queryForObject("SELECT stats IS NULL FROM iac_jobs WHERE job_id = ?", Boolean.class, jobId))
                .isTrue();
        assertThat(service.claimNextJob(IacJobKind.ENRICH_GRAPH)).isEmpty();

        jdbc.update("UPDATE iac_jobs SET available_at = clock_timestamp() - INTERVAL '1 second' WHERE job_id = ?", jobId);
        var second = service.claimNextJob(IacJobKind.ENRICH_GRAPH).orElseThrow();
        assertThat(second.attemptNo()).isEqualTo(2);
        assertThat(second.leaseToken()).isNotEqualTo(first.leaseToken());
        assertThat(service.fail(jobId, first.leaseToken(), IacJobFailureCode.GRAPH_UNAVAILABLE, false)).isFalse();
        assertThat(service.renewLease(jobId, second.leaseToken())).isTrue();
        assertThat(service.complete(jobId, second.leaseToken())).isTrue();
        assertThat(jdbc.queryForObject("SELECT status FROM iac_jobs WHERE job_id = ?", String.class, jobId))
                .isEqualTo("SUCCEEDED");
    }

    @Test
    void retriesStopAtMaxAttemptsAndTheRunBecomesError() {
        long run = run();
        long jobId = job("ANALYZE_RUN", run);
        for (int attempt = 1; attempt <= 3; attempt++) {
            jdbc.update("UPDATE iac_jobs SET available_at = clock_timestamp() - INTERVAL '1 second' WHERE job_id = ?", jobId);
            var claimed = service.claimNextJob(IacJobKind.ANALYZE_RUN).orElseThrow();
            assertThat(claimed.attemptNo()).isEqualTo(attempt);
            assertThat(service.fail(jobId, claimed.leaseToken(), IacJobFailureCode.GRAPH_UNAVAILABLE, true)).isTrue();
        }
        assertThat(jdbc.queryForObject("SELECT status || '/' || last_error_code FROM iac_jobs WHERE job_id = ?",
                String.class, jobId)).isEqualTo("FAILED/GRAPH_UNAVAILABLE");
        assertThat(jdbc.queryForObject("SELECT status FROM iac_runs WHERE run_id = ?", String.class, run))
                .isEqualTo("ERROR");
    }

    @Test
    void doneOrSupersededRunsAreNotTurnedIntoErrors() {
        long run = run();
        jdbc.update("UPDATE iac_runs SET status = 'SUPERSEDED' WHERE run_id = ?", run);
        long jobId = job("ANALYZE_RUN", run);
        var claimed = service.claimNextJob(IacJobKind.ANALYZE_RUN).orElseThrow();
        service.fail(jobId, claimed.leaseToken(), IacJobFailureCode.PLAN_INVALID, false);
        assertThat(jdbc.queryForObject("SELECT status FROM iac_runs WHERE run_id = ?", String.class, run))
                .isEqualTo("SUPERSEDED");
    }

    @Test
    void deletesOnlyExpiredPlanPayloads() {
        long expired = run();
        long fresh = run();
        jdbc.update("""
                INSERT INTO iac_plan_payloads (run_id, content, size_bytes, expires_at)
                VALUES (?, '\\x00', 1, clock_timestamp() - INTERVAL '1 second'),
                       (?, '\\x00', 1, clock_timestamp() + INTERVAL '1 hour')
                """, expired, fresh);
        assertThat(service.deleteExpiredPlans()).isEqualTo(1);
        assertThat(jdbc.queryForList("SELECT run_id FROM iac_plan_payloads", Long.class)).containsExactly(fresh);
    }

    @Test
    void processorFailuresAreStoredAsCodesOnly(CapturedOutput output) {
        long run = run();
        long jobId = job("ANALYZE_RUN", run);
        var poller = new IacJobPoller(service, properties(), new StaticListableBeanFactory().getBeanProvider(IacJobProcessor.class));

        var claimed = service.claimNextJob(IacJobKind.ANALYZE_RUN).orElseThrow();
        poller.processOne(processor((job, execution) -> {
            throw new IllegalStateException("plan content password=hunter2");
        }), claimed);
        assertThat(jdbc.queryForObject("SELECT status || '/' || last_error_code FROM iac_jobs WHERE job_id = ?",
                String.class, jobId)).isEqualTo("PENDING/PROCESSOR_FAILURE");
        assertThat(output.getAll()).doesNotContain("hunter2");

        jdbc.update("UPDATE iac_jobs SET available_at = clock_timestamp() - INTERVAL '1 second' WHERE job_id = ?", jobId);
        var again = service.claimNextJob(IacJobKind.ANALYZE_RUN).orElseThrow();
        poller.processOne(processor((job, execution) -> {
            throw new IacJobFailure(IacJobFailureCode.PLAN_INVALID, false);
        }), again);
        assertThat(jdbc.queryForObject("SELECT status || '/' || last_error_code FROM iac_jobs WHERE job_id = ?",
                String.class, jobId)).isEqualTo("FAILED/PLAN_INVALID");
        assertThat(jdbc.queryForObject("SELECT status FROM iac_runs WHERE run_id = ?", String.class, run))
                .isEqualTo("ERROR");
    }

    @Test
    void pollerWithoutProcessorsLeavesJobsUntouched() {
        job("ENRICH_GRAPH", null);
        new IacJobPoller(service, properties(), new StaticListableBeanFactory().getBeanProvider(IacJobProcessor.class))
                .poll();
        assertThat(jdbc.queryForObject("SELECT status FROM iac_jobs", String.class)).isEqualTo("PENDING");
    }

    private interface Body {
        void run(ClaimedIacJob job, IacJobExecutionService execution);
    }

    private static IacJobProcessor processor(Body body) {
        return new IacJobProcessor() {
            @Override
            public IacJobKind kind() {
                return IacJobKind.ANALYZE_RUN;
            }

            @Override
            public void process(ClaimedIacJob job, IacJobExecutionService execution) {
                body.run(job, execution);
            }
        };
    }

    private static IacJobProperties properties() {
        return new IacJobProperties(true, Duration.ofSeconds(1), Duration.ofMinutes(5), 10,
                Duration.ofSeconds(30), Duration.ofMinutes(30), Duration.ofMinutes(5));
    }

    private static IacJobExecutionService newService() {
        return new IacJobExecutionService(new IacJobRepository(jdbc), properties(), transactions);
    }

    private static long run() {
        long repo = jdbc.queryForObject("""
                INSERT INTO iac_repos (full_name, default_branch, environment)
                VALUES ('test/repo-' || gen_random_uuid(), 'main', 'PROD')
                RETURNING repo_id
                """, Long.class);
        return jdbc.queryForObject("""
                INSERT INTO iac_runs (repo_id, pr_number, head_sha, trigger_type, status)
                VALUES (?, 1, repeat('a', 40), 'PR', 'ANALYZING')
                RETURNING run_id
                """, Long.class, repo);
    }

    private static long job(String kind, Long runId) {
        return jdbc.queryForObject("""
                INSERT INTO iac_jobs (kind, trigger_type, run_id) VALUES (?, 'PR', ?) RETURNING job_id
                """, Long.class, kind, runId);
    }
}
