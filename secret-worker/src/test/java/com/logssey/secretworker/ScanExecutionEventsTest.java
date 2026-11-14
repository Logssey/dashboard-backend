package com.logssey.secretworker;

import static com.logssey.secret.run.progress.core.ScanExecutionObserver.*;
import static org.assertj.core.api.Assertions.*;

import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

class ScanExecutionEventsTest {
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static JdbcTemplate jdbc;
    private static DataSourceTransactionManager transactions;
    private SecretJobExecutionService execution;
    private ClaimedSecretJob job;
    private long runScope;

    @BeforeAll static void database() {
        POSTGRES.start();
        var source = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(source).load().migrate();
        jdbc = new JdbcTemplate(source);
        transactions = new DataSourceTransactionManager(source);
    }
    @AfterAll static void close() { POSTGRES.stop(); }
    @BeforeEach void prepare() {
        jdbc.execute("TRUNCATE secret_connections RESTART IDENTITY CASCADE");
        long connection = jdbc.queryForObject("""
                INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version)
                VALUES('GITHUB','Scan test','test-only-ref','ACTIVE',1) RETURNING connection_id
                """, Long.class);
        long scope = jdbc.queryForObject("""
                INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,history_limit,enabled)
                VALUES(?,'test',1,'GITHUB_REPOSITORY_FILES','Logssey/test-find-key@main:fixtures/','CURRENT_COMMIT_ONLY',true)
                RETURNING scope_id
                """, Long.class, connection);
        long id = jdbc.queryForObject("INSERT INTO secret_jobs(connection_id,kind,status,max_attempts,attempt_no,scheduled_at,available_at) VALUES(?,'FULL_SCAN','PENDING',3,0,clock_timestamp()-interval '1 minute',clock_timestamp()-interval '1 minute') RETURNING job_id", Long.class, connection);
        long run = jdbc.queryForObject("INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,collection_status,detection_status,validation_status,result_status) VALUES(?,?,'MANUAL',1,clock_timestamp(),clock_timestamp(),'PENDING','PENDING','PENDING','PENDING') RETURNING run_id", Long.class, id, connection);
        runScope = jdbc.queryForObject("INSERT INTO secret_run_scopes(run_id,scope_id,collection_status) VALUES(?,?,'PENDING') RETURNING run_scope_id", Long.class, run, scope);
        execution = new SecretJobExecutionService(new SecretJobRepository(jdbc),
                new SecretJobProperties(false, Duration.ofSeconds(30), Duration.ofMinutes(5), 10,
                        Duration.ofSeconds(1), Duration.ofSeconds(4)), transactions);
        job = execution.claimNextJob().orElseThrow();
    }

    @Test void onlyRealObservationsStartStagesAndReasonsAreAllowlisted() {
        jdbc.update("UPDATE secret_scan_runs SET collection_status='RUNNING',detection_status='RUNNING',validation_status='RUNNING' WHERE run_id=?", job.runId());
        assertThat(count("stage='DETECTION'")).isZero();
        String marker = "raw-provider-body-secret-never-store";
        var trace = execution.observer(job, runScope);
        trace.measure(Stage.DETECTION, Operation.GITLEAKS_SCAN, () -> 0);
        trace.record(Stage.DETECTION, Operation.CANDIDATE_NORMALIZATION, Outcome.FAILED, null, marker, null, null, 2L);
        assertThat(count("stage='DETECTION'")).isEqualTo(3);
        assertThat(jdbc.queryForObject("SELECT completed_objects FROM secret_run_execution_stage_facts WHERE run_id=? AND stage='DETECTION'", Long.class, job.runId())).isEqualTo(1);
        assertThat(jdbc.queryForList("SELECT * FROM secret_run_execution_events").toString()).doesNotContain(marker);
        assertThat(jdbc.queryForObject("SELECT reason_code FROM secret_run_execution_events WHERE operation_code='CANDIDATE_NORMALIZATION'", String.class)).isEqualTo("OPERATION_FAILED");
    }

    @Test void expiredAndPriorAttemptCannotAppend() {
        var prior = job;
        jdbc.update("UPDATE secret_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE job_id=?", job.jobId());
        assertThatThrownBy(() -> execution.observer(prior, runScope).record(Stage.COLLECTION, Operation.GITHUB_REF_GET,
                Outcome.COMPLETED, 200, null, null, null, 1L)).isInstanceOf(SecretJobFailure.class);
        execution.recoverExpiredJobs();
        jdbc.update("UPDATE secret_jobs SET available_at=clock_timestamp()-interval '1 second' WHERE job_id=?", job.jobId());
        job = execution.claimNextJob().orElseThrow();
        assertThat(job.attemptNo()).isEqualTo(2);
        assertThatThrownBy(() -> execution.observer(prior, runScope).record(Stage.DETECTION, Operation.GITLEAKS_SCAN,
                Outcome.COMPLETED, null, null, null, null, 1L)).isInstanceOf(SecretJobFailure.class);
        assertThat(count("operation_code='GITLEAKS_SCAN'")).isZero();
        assertThat(count("outcome='RETRY_SCHEDULED'")).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_run_execution_stage_facts WHERE run_id=? AND attempt_no=2 AND stage='DETECTION'", Long.class, job.runId())).isZero();
    }

    @Test void duplicateObservationAndRollbackDoNotCreateFalseHistory() {
        String id = UUID.randomUUID().toString();
        assertThat(append(id)).isTrue();
        assertThat(append(id)).isTrue();
        assertThat(count("operation_code='GITLEAKS_SCAN'")).isEqualTo(1);
        assertThatThrownBy(() -> execution.persistIfLeased(job.jobId(), job.leaseToken(), () -> {
            execution.observer(job, runScope).record(Stage.DETECTION, Operation.FINDINGS_COMMIT,
                    Outcome.COMPLETED, null, null, 3L, null, 2L);
            throw new IllegalStateException("ROLLBACK");
        })).isInstanceOf(IllegalStateException.class);
        assertThat(count("operation_code='FINDINGS_COMMIT'")).isZero();
    }

    @Test void detailCapPreservesStageCountersAndFinalLifecycle() {
        jdbc.queryForList("""
                SELECT secret_record_execution_event(?,?::uuid,?,?,'DETECTION','GITLEAKS_SCAN','COMPLETED',
                 NULL,NULL,NULL,NULL,1,'detail:'||i) FROM generate_series(1,1005) AS i
                """, job.jobId(), job.leaseToken(), job.leaseGeneration(), runScope);
        assertThat(count("NOT lifecycle")).isEqualTo(1000);
        assertThat(jdbc.queryForObject("SELECT execution_suppressed_count FROM secret_scan_runs WHERE run_id=?", Long.class, job.runId())).isEqualTo(5);
        assertThat(jdbc.queryForObject("SELECT completed_objects FROM secret_run_execution_stage_facts WHERE run_id=? AND stage='DETECTION'", Long.class, job.runId())).isEqualTo(1005);
        terminalScopes();
        assertThat(execution.complete(job.jobId(), job.leaseToken())).isTrue();
        assertThat(count("stage='RESULT' AND outcome='COMPLETED'")).isEqualTo(1);
        assertThat(count("operation_code='STAGE_SUMMARY' AND stage='VALIDATION' AND outcome='SKIPPED'")).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT max(event_id)=count(*) FROM secret_run_execution_events WHERE run_id=?", Boolean.class, job.runId())).isTrue();
    }

    @Test void concurrentCommitOrderingLeavesNoCursorHole() throws Exception {
        long before = jdbc.queryForObject("SELECT max(event_id) FROM secret_run_execution_events WHERE run_id=?", Long.class, job.runId());
        var firstWritten = new java.util.concurrent.CountDownLatch(1);
        var release = new java.util.concurrent.CountDownLatch(1);
        try (var pool = Executors.newFixedThreadPool(2)) {
            var first = pool.submit(() -> new TransactionTemplate(transactions).execute(status -> {
                append("first");
                firstWritten.countDown();
                try { release.await(5, TimeUnit.SECONDS); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                return null;
            }));
            assertThat(firstWritten.await(5, TimeUnit.SECONDS)).isTrue();
            var second = pool.submit(() -> append("second"));
            assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_run_execution_events WHERE run_id=? AND event_id>?", Long.class, job.runId(), before)).isZero();
            release.countDown();
            first.get(5, TimeUnit.SECONDS);
            assertThat(second.get(5, TimeUnit.SECONDS)).isTrue();
        }
        assertThat(jdbc.queryForList("SELECT event_key FROM secret_run_execution_events WHERE run_id=? AND event_id>? ORDER BY event_id", String.class, job.runId(), before)).containsExactly("first", "second");
    }

    @Test void terminalEventsExpireWithoutDeletingStageFactsOrInventingLegacyHistory() {
        execution.observer(job, runScope).record(Stage.DETECTION, Operation.GITLEAKS_SCAN, Outcome.COMPLETED, null, null, null, null, 1L);
        terminalScopes();
        assertThat(execution.complete(job.jobId(), job.leaseToken())).isTrue();
        jdbc.update("UPDATE secret_scan_runs SET finished_at=clock_timestamp()-interval '31 days' WHERE run_id=?", job.runId());
        assertThat(jdbc.queryForObject("SELECT secret_purge_execution_events()", Long.class)).isPositive();
        assertThat(count("true")).isZero();
        assertThat(jdbc.queryForObject("SELECT execution_events_expired_at IS NOT NULL FROM secret_scan_runs WHERE run_id=?", Boolean.class, job.runId())).isTrue();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_run_execution_stage_facts WHERE run_id=?", Long.class, job.runId())).isPositive();
    }

    @Test void nonOwnerWorkerCanOnlyWriteThroughTheLiveFenceAndCannotShadowTrustedTables() {
        jdbc.execute("CREATE ROLE execution_trace_test_worker NOLOGIN NOINHERIT");
        jdbc.execute("GRANT USAGE ON SCHEMA public TO execution_trace_test_worker");
        jdbc.execute("GRANT EXECUTE ON FUNCTION secret_record_execution_event(bigint,uuid,bigint,bigint,text,text,text,integer,text,bigint,bigint,bigint,text),secret_purge_execution_events() TO execution_trace_test_worker");
        var transaction = new TransactionTemplate(transactions);
        Boolean accepted = transaction.execute(status -> {
            jdbc.execute("SET LOCAL ROLE execution_trace_test_worker");
            return append("nonowner");
        });
        assertThat(accepted).isTrue();
        assertThat(count("event_key='nonowner'")).isEqualTo(1);
        for (String forbidden : java.util.List.of(
                "SELECT secret_append_execution_event(1,NULL,1,1,'COLLECTION','SCOPE_COLLECTION','STARTED',NULL,NULL,NULL,NULL,NULL,'bypass',true)",
                "INSERT INTO secret_run_execution_events(run_id,event_id,event_key,attempt_no,lease_generation,stage,operation_code,outcome,lifecycle) VALUES(1,2000,'bypass',1,1,'DETECTION','GITLEAKS_SCAN','COMPLETED',false)",
                "UPDATE secret_run_execution_stage_facts SET completed_objects=99999",
                "DELETE FROM secret_run_execution_events")) {
            assertThatThrownBy(() -> transaction.execute(status -> {
                jdbc.execute("SET LOCAL ROLE execution_trace_test_worker");
                jdbc.execute(forbidden);
                return null;
            })).isInstanceOf(org.springframework.dao.DataAccessException.class);
        }
        Boolean forged = transaction.execute(status -> {
            jdbc.execute("SET LOCAL ROLE execution_trace_test_worker");
            jdbc.execute("CREATE TEMPORARY TABLE secret_jobs(job_id bigint,status text,lease_token uuid,lease_generation bigint,lease_until timestamptz,attempt_no integer)");
            jdbc.update("INSERT INTO secret_jobs VALUES(?,'LEASED','33333333-3333-3333-3333-333333333333',1,clock_timestamp()+interval '5 minutes',1)", job.jobId());
            return jdbc.queryForObject("SELECT secret_record_execution_event(?,'33333333-3333-3333-3333-333333333333'::uuid,1,NULL,'DETECTION','GITLEAKS_SCAN','COMPLETED',NULL,NULL,NULL,NULL,1,'forged')", Boolean.class, job.jobId());
        });
        assertThat(forged).isFalse();
        assertThat(count("event_key='forged'")).isZero();
        assertThatThrownBy(() -> transaction.execute(status -> {
            jdbc.execute("SET LOCAL ROLE execution_trace_test_worker");
            jdbc.execute("CREATE TEMPORARY TABLE forged_job_events(job_id bigint,status text,attempt_no integer)");
            jdbc.execute("CREATE TRIGGER forged AFTER UPDATE ON forged_job_events FOR EACH ROW EXECUTE FUNCTION public.secret_execution_job_transition()");
            return null;
        })).isInstanceOf(org.springframework.dao.DataAccessException.class);
        // Real ledger updates still invoke their owner-installed trigger for a non-owner worker.
        jdbc.execute("GRANT SELECT,UPDATE ON secret_run_scopes TO execution_trace_test_worker");
        transaction.executeWithoutResult(status -> {
            jdbc.execute("SET LOCAL ROLE execution_trace_test_worker");
            jdbc.update("UPDATE secret_run_scopes SET collection_status='RUNNING' WHERE run_scope_id=?", runScope);
        });
        assertThat(count("operation_code='SCOPE_COLLECTION' AND outcome='STARTED'")).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT bool_and(prosecdef) FROM pg_proc WHERE proname IN('secret_record_execution_event','secret_purge_execution_events')", Boolean.class)).isTrue();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM pg_proc WHERE proname IN('secret_record_execution_event','secret_purge_execution_events') AND pg_get_userbyid(proowner)='execution_trace_test_worker'", Long.class)).isZero();
    }

    private boolean append(String id) {
        return jdbc.queryForObject("""
                SELECT secret_record_execution_event(?,?::uuid,?,?,'DETECTION','GITLEAKS_SCAN','COMPLETED',NULL,NULL,NULL,NULL,1,?)
                """, Boolean.class, job.jobId(), job.leaseToken(), job.leaseGeneration(), runScope, id);
    }
    private long count(String condition) {
        return jdbc.queryForObject("SELECT count(*) FROM secret_run_execution_events WHERE run_id=? AND " + condition, Long.class, job.runId());
    }
    private void terminalScopes() {
        execution.persistIfLeased(job.jobId(), job.leaseToken(), () -> {
            jdbc.update("UPDATE secret_run_scopes SET collection_status='SUCCEEDED',object_count=0,started_at=clock_timestamp(),finished_at=clock_timestamp() WHERE run_id=?", job.runId());
            jdbc.update("UPDATE secret_scan_runs SET collection_status='SUCCEEDED',detection_status='SKIPPED',validation_status='SKIPPED' WHERE run_id=?", job.runId());
        });
    }
}
