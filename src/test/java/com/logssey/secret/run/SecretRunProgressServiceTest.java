package com.logssey.secret.run;

import static org.assertj.core.api.Assertions.*;
import com.logssey.common.error.ApiException;
import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.command.SecretCommandExecutor;
import com.logssey.secret.run.progress.SecretRunProgress;
import com.logssey.secret.run.progress.SecretRunProgressService;
import java.time.OffsetDateTime;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

class SecretRunProgressServiceTest {
    private static final PostgreSQLContainer POSTGRES = new com.logssey.secret.testing.SecretTestPostgres();
    private static JdbcTemplate jdbc;
    private static DataSourceTransactionManager transactions;
    private SecretRunProgressService progress;
    private long run;
    private long job;
    private long scope;

    @BeforeAll static void database() {
        POSTGRES.start();
        var source = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(source).load().migrate();
        jdbc = new JdbcTemplate(source);
        transactions = new DataSourceTransactionManager(source);
    }
    @AfterAll static void close() { POSTGRES.stop(); }
    @BeforeEach void prepare() {
        jdbc.execute("TRUNCATE secret_connections,dashboard_users RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO dashboard_users(login_id,password_hash,display_name,role) VALUES('progress-admin','test-hash','Operator','ADMIN')");
        jdbc.update("INSERT INTO secret_role_grants(user_id,role,granted_by_user_id,grant_source) VALUES(1,'OPERATIONS',1,'MANUAL'),(1,'SECURITY',1,'MANUAL')");
        long connection = jdbc.queryForObject("INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version) VALUES('GITHUB','Private name','test-only-ref','ACTIVE',1) RETURNING connection_id", Long.class);
        jdbc.update("""
                INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,history_limit,enabled)
                VALUES(?,'test',1,'GITHUB_REPOSITORY_FILES','Logssey/test-find-key@main:fixtures/','CURRENT_COMMIT_ONLY',true)
                """, connection);
        var access = new SecretAccessService(jdbc);
        var runs = new SecretRunService(new SecretRunRepository(jdbc), transactions, access, new SecretCommandExecutor(jdbc, transactions));
        run = runs.register(new SecretRunRequest(connection, "progress-registration"), "progress-admin").runId();
        job = jdbc.queryForObject("SELECT job_id FROM secret_scan_runs WHERE run_id=?", Long.class, run);
        scope = jdbc.queryForObject("SELECT run_scope_id FROM secret_run_scopes WHERE run_id=?", Long.class, run);
        progress = new SecretRunProgressService(jdbc, runs, access);
    }

    @Test void queueAndNullableCountsAreActualAndRegistrationIsIdempotent() {
        var first = read(0, 100);
        assertThat(first.status()).isEqualTo("PENDING");
        assertThat(first.eventsStatus()).isEqualTo("AVAILABLE");
        assertThat(first.events()).hasSize(1);
        assertThat(first.events().getFirst().operationCode()).isEqualTo("RUN_REGISTERED");
        assertThat(first.collectedObjectCount()).isNull();
        assertThat(first.findingCount()).isNull();
        assertThat(first.stages()).extracting(SecretRunProgress.Stage::key).containsExactly("QUEUE", "COLLECTION", "DETECTION", "VALIDATION", "RESULT");
        assertThat(first.stages()).allSatisfy(stage -> assertThat(stage.status()).isEqualTo("PENDING"));
        assertThat(first.requestedAt()).isNotNull();
        assertThat(first.pollAfterMs()).isEqualTo(2500);
        assertThat(read(first.nextAfterEventId(), 100).events()).isEmpty();
    }

    @Test void collectionDetectionAndValidationCanBeConcurrentWithoutEagerFalseStarts() {
        claim();
        jdbc.update("UPDATE secret_scan_runs SET collection_status='RUNNING',detection_status='RUNNING',validation_status='RUNNING' WHERE run_id=?", run);
        assertThat(read(0, 100).stages().stream().filter(s -> !s.key().equals("QUEUE"))).allSatisfy(stage -> assertThat(stage.status()).isEqualTo("PENDING"));
        event("COLLECTION", "GITHUB_BLOB_GET", "STARTED", "collection");
        event("DETECTION", "GITLEAKS_SCAN", "STARTED", "detect");
        event("VALIDATION", "GITHUB_CREDENTIAL_CHECK", "STARTED", "validation");
        var current = read(0, 100);
        assertThat(current.stages().stream().filter(s -> java.util.Set.of("COLLECTION", "DETECTION", "VALIDATION").contains(s.key())))
                .allSatisfy(stage -> assertThat(stage.status()).isEqualTo("RUNNING"));
        assertThat(current.stages().getLast().status()).isEqualTo("PENDING");
    }

    @Test void cursorPagingIsOrderedAndAccessIsCheckedAgainOnResume() {
        claim();
        event("COLLECTION", "GITHUB_REF_GET", "STARTED", "first");
        event("COLLECTION", "GITHUB_REF_GET", "COMPLETED", "second");
        var first = read(0, 2);
        var second = read(first.nextAfterEventId(), 2);
        assertThat(first.hasMore()).isTrue();
        assertThat(second.events()).hasSize(2);
        assertThat(second.events()).allSatisfy(event -> assertThat(event.id()).isGreaterThan(first.nextAfterEventId()));
        assertThat(second.hasMore()).isFalse();
        jdbc.update("UPDATE secret_role_grants SET revoked_at=clock_timestamp() WHERE user_id=1");
        assertThatThrownBy(() -> read(second.nextAfterEventId(), 2)).isInstanceOf(ApiException.class);
    }

    @Test void metadataStagesAreSkippedAndPartialScopeCountIsNeverDoubled() {
        claim();
        jdbc.update("UPDATE secret_run_scopes SET snapshot_content_type='IAM_ACCESS_KEY_METADATA',collection_status='PARTIAL',object_count=2,finished_at=clock_timestamp(),detection_reason_code='NOT_APPLICABLE_METADATA',validation_reason_code='NOT_APPLICABLE_METADATA' WHERE run_id=?", run);
        jdbc.update("UPDATE secret_jobs SET status='SUCCEEDED',lease_owner=NULL,lease_until=NULL,finished_at=clock_timestamp() WHERE job_id=?", job);
        jdbc.update("UPDATE secret_scan_runs SET collection_status='PARTIAL',detection_status='SKIPPED',validation_status='SKIPPED',result_status='PARTIAL',finished_at=clock_timestamp() WHERE run_id=?", run);
        var result = read(0, 100);
        assertThat(result.finishedScopeCount()).isEqualTo(1);
        assertThat(result.collectedObjectCount()).isEqualTo(2);
        assertThat(result.stages().stream().filter(s -> java.util.Set.of("DETECTION", "VALIDATION").contains(s.key())))
                .allSatisfy(stage -> { assertThat(stage.status()).isEqualTo("SKIPPED"); assertThat(stage.reasonCode()).isEqualTo("NOT_APPLICABLE_METADATA"); });
    }

    @Test void legacyAndExpiredHistoryRemainExplicitWithoutInventedLines() {
        jdbc.update("DELETE FROM secret_run_execution_events WHERE run_id=?", run);
        jdbc.update("UPDATE secret_scan_runs SET execution_trace_version=NULL,execution_event_count=0 WHERE run_id=?", run);
        assertThat(read(0, 100).eventsStatus()).isEqualTo("NOT_RECORDED");
        assertThat(read(0, 100).historyComplete()).isFalse();
        jdbc.update("UPDATE secret_scan_runs SET execution_trace_version=1,execution_events_expired_at=clock_timestamp() WHERE run_id=?", run);
        assertThat(read(0, 100).eventsStatus()).isEqualTo("EXPIRED");
        assertThat(read(0, 100).expiredAt()).isNotNull();
    }

    @Test void retryWaitingClearsActiveStagePresentationAndNeverInheritsEarlierSuccess() {
        claim();
        event("DETECTION", "GITLEAKS_SCAN", "STARTED", "old-start");
        event("DETECTION", "GITLEAKS_SCAN", "COMPLETED", "old-end");
        jdbc.update("UPDATE secret_scan_runs SET collection_status='SUCCEEDED',detection_status='SUCCEEDED',validation_status='PENDING',result_status='PENDING' WHERE run_id=?", run);
        jdbc.update("UPDATE secret_jobs SET status='PENDING',lease_owner=NULL,lease_until=NULL,available_at=clock_timestamp()+interval '1 minute',last_error_code='VALIDATOR_TEMPORARY' WHERE job_id=?", job);
        assertThat(read(0, 100).stages().stream().filter(stage -> !stage.key().equals("QUEUE")))
                .allSatisfy(stage -> { assertThat(stage.status()).isEqualTo("PENDING"); assertThat(stage.startedAt()).isNull(); assertThat(stage.processedCount()).isNull(); });
        jdbc.update("UPDATE secret_jobs SET status='LEASED',attempt_no=2,lease_owner='second',lease_token='22222222-2222-2222-2222-222222222222',lease_generation=2,lease_until=clock_timestamp()+interval '5 minutes' WHERE job_id=?", job);
        jdbc.update("UPDATE secret_scan_runs SET result_status='RUNNING' WHERE run_id=?", run);
        assertThat(read(0, 100).stages().stream().filter(stage -> !stage.key().equals("QUEUE")))
                .allSatisfy(stage -> assertThat(stage.status()).isEqualTo("PENDING"));
        jdbc.update("UPDATE secret_jobs SET status='FAILED',lease_owner=NULL,lease_until=NULL,finished_at=clock_timestamp() WHERE job_id=?", job);
        jdbc.update("UPDATE secret_scan_runs SET validation_status='FAILED',result_status='FAILED',finished_at=clock_timestamp() WHERE run_id=?", run);
        assertThat(read(0, 100).stages().stream().filter(stage -> stage.key().equals("DETECTION"))).singleElement()
                .satisfies(stage -> { assertThat(stage.status()).isEqualTo("UNKNOWN"); assertThat(stage.reasonCode()).isEqualTo("STAGE_NOT_OBSERVED"); });
    }

    @Test void cancellationEndsPendingStagesWhilePreservingCompletedAndSkippedFacts() {
        claim();
        event("COLLECTION", "SCOPE_COLLECTION", "STARTED", "collected-start");
        jdbc.update("UPDATE secret_scan_runs SET collection_status='SUCCEEDED',detection_status='SKIPPED',validation_status='PENDING' WHERE run_id=?", run);
        jdbc.update("UPDATE secret_jobs SET status='CANCELLED',last_error_code='APPROVAL_CHANGED',lease_owner=NULL,lease_until=NULL,finished_at=clock_timestamp() WHERE job_id=?", job);
        var current = read(0, 100);
        assertThat(current.status()).isEqualTo("CANCELLED");
        assertThat(current.finishedAt()).isEqualTo(jdbc.queryForObject("SELECT finished_at FROM secret_jobs WHERE job_id=?", java.time.OffsetDateTime.class, job));
        assertThat(current.stages().stream().filter(stage -> stage.key().equals("COLLECTION"))).singleElement()
                .satisfies(stage -> assertThat(stage.status()).isEqualTo("SUCCEEDED"));
        assertThat(current.stages().stream().filter(stage -> stage.key().equals("DETECTION"))).singleElement()
                .satisfies(stage -> assertThat(stage.status()).isEqualTo("SKIPPED"));
        assertThat(current.stages().stream().filter(stage -> stage.key().equals("VALIDATION"))).singleElement()
                .satisfies(stage -> { assertThat(stage.status()).isEqualTo("CANCELLED"); assertThat(stage.reasonCode()).isEqualTo("APPROVAL_CHANGED"); });
        assertThat(current.stages()).noneSatisfy(stage -> assertThat(stage.status()).isEqualTo("RUNNING"));
    }

    @Test void invalidCursorSizeAndNotFoundAreRejected() {
        assertThatThrownBy(() -> read(-1, 100)).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> read(2, 100)).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> read(0, 201)).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> progress.progress("progress-admin", 999999, 0, 100)).isInstanceOf(ApiException.class);
    }

    @Test void reuseSupportIsExplicitForHistoricalRunsAndEveryWorkerAttempt() {
        assertThat(read(0, 100).validationSummary().reuseRecorded()).isFalse();
        assertThat(read(0, 100).validationSummary().reusedResultCount()).isNull();
        claim();
        jdbc.update("UPDATE secret_scan_runs SET validation_reuse_version=1,validation_reuse_attempt=1 WHERE run_id=?", run);
        assertThat(read(0, 100).validationSummary().reuseRecorded()).isTrue();
        assertThat(read(0, 100).validationSummary().reusedResultCount()).isZero();
        jdbc.update("UPDATE secret_jobs SET attempt_no=2,lease_generation=2 WHERE job_id=?", job);
        assertThat(read(0, 100).validationSummary().reuseRecorded()).isFalse();
        assertThat(read(0, 100).validationSummary().reusedResultCount()).isNull();
    }

    @Test void progressSeparatesSevenReusedObservationsFromTwoIncompleteCurrentDecisions() {
        claim();
        var sourceAttempts = new java.util.ArrayList<Long>();
        for (int index = 0; index < 7; index++) {
            sourceAttempts.add(validationAttempt(index, "INVALID", "INVALID_ACCESS_KEY"));
        }
        jdbc.update("UPDATE secret_jobs SET attempt_no=2,lease_generation=2 WHERE job_id=?", job);
        jdbc.update("UPDATE secret_scan_runs SET validation_reuse_version=1,validation_reuse_attempt=2 WHERE run_id=?", run);
        for (long source : sourceAttempts) {
            jdbc.update("""
                    INSERT INTO secret_validation_reuses(run_id,run_scope_id,attempt_no,credential_set_id,source_attempt_id)
                    SELECT ?,?,2,credential_set_id,attempt_id FROM secret_validation_attempts WHERE attempt_id=?
                    """, run, scope, source);
        }
        validationAttempt(8, "UNCHECKED", "INCOMPLETE_PAIR");
        validationAttempt(9, "UNCHECKED", "MISSING_SESSION_TOKEN");
        var summary = read(0, 100).validationSummary();
        assertThat(summary.reuseRecorded()).isTrue();
        assertThat(summary.newRequestCount()).isZero();
        assertThat(summary.completedRequestCount()).isZero();
        assertThat(summary.reusedResultCount()).isEqualTo(7);
        assertThat(summary.uncheckedCount()).isEqualTo(2);
        assertThat(summary.incompleteCount()).isEqualTo(2);
        assertThat(summary.unknownCount()).isZero();
        assertThat(summary.reusedResults()).hasSize(7).allSatisfy(result -> {
            assertThat(result.result()).isEqualTo("INVALID");
            assertThat(result.sourceRunId()).isEqualTo(run);
            assertThat(result.providerCheckedAt()).isBefore(OffsetDateTime.now().minusSeconds(20));
            assertThat(result.count()).isEqualTo(1);
        });
        assertThat(summary.reusedResultsTruncated()).isFalse();
        var next = validationAttempt(10, "INVALID", "INVALID_ACCESS_KEY");
        var withNewRequest = read(0, 100).validationSummary();
        assertThat(withNewRequest.newRequestCount()).isEqualTo(1);
        assertThat(withNewRequest.completedRequestCount()).isEqualTo(1);
        assertThat(withNewRequest.reusedResultCount()).isEqualTo(7);
        assertThat(jdbc.queryForObject("SELECT request_sent_at IS NOT NULL FROM secret_validation_attempts WHERE attempt_id=?", Boolean.class, next)).isTrue();
    }

    private long validationAttempt(int index, String result, String reason) {
        long credential = jdbc.queryForObject("""
                INSERT INTO secret_credential_sets(issuer,credential_type,component_state,fingerprint,fingerprint_key_version,first_seen_at,last_seen_at)
                VALUES('AWS','AWS_ACCESS_KEY_PAIR','CONFIRMED',sha256(convert_to(?,'UTF8')),'test-v1',clock_timestamp(),clock_timestamp()) RETURNING credential_set_id
                """, Long.class, "progress-credential-" + index);
        long occurrence = jdbc.queryForObject("""
                INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,
                 environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at)
                SELECT ?,r.connection_id,s.scope_id,?,'L1','UNKNOWN','UNKNOWN','UNKNOWN','PRESENT',clock_timestamp(),clock_timestamp()
                FROM secret_run_scopes s JOIN secret_scan_runs r USING(run_id) WHERE s.run_scope_id=? RETURNING occurrence_id
                """, Long.class, credential, "private/progress-" + index, scope);
        return jdbc.queryForObject("""
                INSERT INTO secret_validation_attempts(evidence_version,credential_set_id,run_id,job_id,validator_id,validator_version,
                 endpoint_class,requested_at,completed_at,provider_checked_at,result,reason_code,attempt_state,request_sent_at,
                 scope_id,occurrence_id,source_object_version_digest,credential_revision,scope_revision,validation_revision,
                 validation_approval_revision,validation_profile_version,action_context_digest,dedup_key,cycle_key,attempt_no,
                 reservation_generation,reservation_token,current_eligible,ineligible_reason_code)
                SELECT 1,?,?,j.job_id,'AWS_STS_GET_CALLER_IDENTITY','v1','AWS_STS',clock_timestamp()-interval '1 minute',
                 clock_timestamp()-interval '30 seconds',CASE WHEN ?<>'UNCHECKED' THEN clock_timestamp()-interval '40 seconds' END,
                 ?,?,'COMPLETED',CASE WHEN ?<>'UNCHECKED' THEN clock_timestamp()-interval '50 seconds' END,
                 s.scope_id,?,decode(repeat('11',32),'hex'),1,1,1,1,'credential-validation-v1',decode(repeat('22',32),'hex'),
                 decode(repeat('33',32),'hex'),'scheduled:test',j.attempt_no,j.lease_generation,j.lease_token,false,'APPROVAL_CHANGED'
                FROM secret_jobs j JOIN secret_scan_runs r USING(job_id) JOIN secret_run_scopes s USING(run_id)
                WHERE j.job_id=? AND s.run_scope_id=? RETURNING attempt_id
                """, Long.class, credential, run, result, result, reason, result, occurrence, job, scope);
    }

    private void claim() {
        jdbc.update("UPDATE secret_jobs SET status='LEASED',attempt_no=1,lease_owner='test',lease_token='11111111-1111-1111-1111-111111111111',lease_generation=1,lease_until=clock_timestamp()+interval '5 minutes' WHERE job_id=?", job);
        jdbc.update("UPDATE secret_scan_runs SET result_status='RUNNING',started_at=clock_timestamp() WHERE run_id=?", run);
    }
    private void event(String stage, String operation, String outcome, String key) {
        jdbc.queryForObject("SELECT secret_record_execution_event(?,'11111111-1111-1111-1111-111111111111'::uuid,1,?,?,?,?,NULL,NULL,NULL,NULL,1,?)", Boolean.class,
                job, scope, stage, operation, outcome, key);
    }
    private SecretRunProgress read(long after, int size) {
        var transaction = new TransactionTemplate(transactions);
        transaction.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
        transaction.setReadOnly(true);
        return transaction.execute(status -> progress.progress("progress-admin", run, after, size));
    }
}
