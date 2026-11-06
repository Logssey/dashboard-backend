package com.logssey.secretworker;

import java.time.Duration;
import java.time.OffsetDateTime;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;

/** Exercises the V10 outcome transition against the actual PostgreSQL schema and job fence. */
class SecretRevalidationResultTest {
    private static final PostgreSQLContainer POSTGRES = new com.logssey.secret.testing.SecretTestPostgres();
    private static JdbcTemplate jdbc;
    private static DataSourceTransactionManager transactions;

    private SecretJobExecutionService execution;
    private Seed seed;

    @BeforeAll
    static void startDatabase() {
        POSTGRES.start();
        var datasource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(),
                POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(datasource).load().migrate();
        jdbc = new JdbcTemplate(datasource);
        transactions = new DataSourceTransactionManager(datasource);
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @BeforeEach
    void seedOneRevalidation() {
        jdbc.execute("TRUNCATE secret_connections RESTART IDENTITY CASCADE");
        jdbc.execute("TRUNCATE dashboard_users RESTART IDENTITY CASCADE");
        seed = seed();
        execution = new SecretJobExecutionService(new SecretJobRepository(jdbc),
                new SecretJobProperties(false, Duration.ofSeconds(30), Duration.ofMinutes(5),
                        10, Duration.ofSeconds(2), Duration.ofSeconds(8)), transactions);
    }

    @Test
    void completeCoverageAndMatchingBaselinesProveOccurrenceMissing() {
        var claim = claim();
        completedEvidence("SUCCEEDED", "SUCCEEDED", "config-v1", "gitleaks-v1", "hmac-v1");

        assertThat(execution.complete(claim.jobId(), claim.leaseToken())).isTrue();
        assertOutcome("MISSING", null, "MISSING", "SUCCEEDED");
        assertThat(jdbc.queryForObject("""
                SELECT last_complete_coverage_at FROM secret_occurrences WHERE occurrence_id = ?
                """, OffsetDateTime.class, seed.occurrenceId())).isNotNull();
    }

    @Test
    void sameCredentialFindingInThisRunKeepsOccurrencePresent() {
        var claim = claim();
        completedEvidence("SUCCEEDED", "SUCCEEDED", "config-v1", "gitleaks-v1", "hmac-v1");
        jdbc.update("""
                INSERT INTO secret_findings
                    (occurrence_id, run_id, tool_run_id, finding_key, rule_id, rule_version,
                     detected_at)
                VALUES (?, ?, ?, 'same-key-found', 'test-rule', 'v1', clock_timestamp())
                """, seed.occurrenceId(), seed.runId(), seed.toolRunId());
        jdbc.update("""
                UPDATE secret_occurrences SET presence_status = 'PRESENT', last_seen_run_id = ?
                WHERE occurrence_id = ?
                """, seed.runId(), seed.occurrenceId());

        assertThat(execution.complete(claim.jobId(), claim.leaseToken())).isTrue();
        assertOutcome("PRESENT", null, "PRESENT", "SUCCEEDED");
    }

    @Test
    void aSuccessfulNotionWalkCannotProveRemovalWithoutASnapshotContract() {
        jdbc.update("UPDATE secret_connection_scopes SET content_type='NOTION_PAGE_CONTENT' WHERE connection_id=?",
                seed.connectionId());
        var claim = claim();
        completedEvidence("SUCCEEDED", "SUCCEEDED", "config-v1", "gitleaks-v1", "hmac-v1");

        assertThat(execution.complete(claim.jobId(), claim.leaseToken())).isTrue();
        assertOutcome("UNKNOWN", "REVALIDATION_INCOMPLETE", "UNKNOWN", "SUCCEEDED");
    }

    @Test
    void partialScopeCannotProveAbsenceEvenWithMatchingDetectorMetadata() {
        var claim = claim();
        completedEvidence("PARTIAL", "SUCCEEDED", "config-v1", "gitleaks-v1", "hmac-v1");

        assertThat(execution.complete(claim.jobId(), claim.leaseToken())).isTrue();
        assertOutcome("UNKNOWN", "REVALIDATION_INCOMPLETE", "UNKNOWN", "PARTIAL");
    }

    @Test
    void configEngineFingerprintOrScopeBaselineMismatchCannotProveAbsence() {
        for (String changed : new String[]{"config", "engine", "fingerprint", "scope"}) {
            if (!"config".equals(changed)) {
                seedOneRevalidation();
            }
            var claim = claim();
            completedEvidence("SUCCEEDED", "SUCCEEDED",
                    "config".equals(changed) ? "config-v2" : "config-v1",
                    "engine".equals(changed) ? "gitleaks-v2" : "gitleaks-v1",
                    "fingerprint".equals(changed) ? "hmac-v2" : "hmac-v1");
            if ("scope".equals(changed)) {
                jdbc.update("UPDATE secret_connections SET scope_version = 2 WHERE connection_id = ?",
                        seed.connectionId());
            }

            assertThat(execution.complete(claim.jobId(), claim.leaseToken()))
                    .as(changed + " baseline mismatch still completes the job").isTrue();
            assertOutcome("UNKNOWN", "REVALIDATION_INCOMPLETE", "UNKNOWN", "SUCCEEDED");
        }
    }

    @Test
    void permanentJobFailureLeavesUnprovenOccurrenceUnknown() {
        var claim = claim();

        assertThat(execution.fail(claim.jobId(), claim.leaseToken(),
                SecretJobFailureCode.SOURCE_UNAVAILABLE, false)).isTrue();
        assertOutcome("UNKNOWN", "SOURCE_UNAVAILABLE", "UNKNOWN", "FAILED");
        assertThat(jdbc.queryForObject("SELECT status FROM secret_jobs WHERE job_id = ?",
                String.class, seed.jobId())).isEqualTo("FAILED");
    }

    @Test void changedRevisionCycleCompletionOrIdentityCannotReuseMissingEvidence(){
        String[] mutations={"UPDATE secret_connection_scopes SET revision=revision+1",
          "UPDATE secret_case_occurrences SET action_cycle=action_cycle+1",
          "UPDATE secret_case_occurrences SET actions_completed_at=clock_timestamp()",
          "UPDATE secret_case_occurrences SET last_material_action_at=clock_timestamp()",
          "UPDATE secret_case_occurrences SET version=version+1",
          "UPDATE secret_credential_sets SET fingerprint=decode(md5(random()::text),'hex')"};
        for(int i=0;i<mutations.length;i++){
            if(i>0)seedOneRevalidation();var claim=claim();completedEvidence("SUCCEEDED","SUCCEEDED","config-v1","gitleaks-v1","hmac-v1");
            jdbc.update(mutations[i]);assertThat(execution.complete(claim.jobId(),claim.leaseToken())).isTrue();
            assertOutcome("UNKNOWN","REVALIDATION_INCOMPLETE","UNKNOWN","SUCCEEDED");
        }
    }
    @Test void legacyRevalidationWithoutCapturedComparisonFactsCannotProveAbsence(){
        var claim=claim();completedEvidence("SUCCEEDED","SUCCEEDED","config-v1","gitleaks-v1","hmac-v1");
        jdbc.update("UPDATE secret_case_revalidations SET scope_revision=NULL,baseline_identity=NULL WHERE run_id=?",seed.runId());
        assertThat(execution.complete(claim.jobId(),claim.leaseToken())).isTrue();assertOutcome("UNKNOWN","REVALIDATION_INCOMPLETE","UNKNOWN","SUCCEEDED");
    }

    private ClaimedSecretJob claim() {
        var claim = execution.claimNextJob().orElseThrow();
        assertThat(claim.jobId()).isEqualTo(seed.jobId());
        // The collection pipeline invalidates old presence before this scan. A failed or
        // incomplete run must not turn that unknown state into proof of absence.
        jdbc.update("UPDATE secret_occurrences SET presence_status = 'UNKNOWN' WHERE occurrence_id = ?",
                seed.occurrenceId());
        return claim;
    }

    private void completedEvidence(String scopeStatus, String detectionStatus, String configHash,
                                   String engineVersion, String fingerprintVersion) {
        String runCollection = "PARTIAL".equals(scopeStatus) ? "PARTIAL" : "SUCCEEDED";
        jdbc.update("""
                UPDATE secret_run_scopes
                SET collection_status = ?, object_count = 1,
                    started_at = clock_timestamp(),detection_stage_status='SUCCEEDED',
                    finished_at = clock_timestamp()
                WHERE run_scope_id = ?
                """, scopeStatus, seed.runScopeId());
        jdbc.update("""
                UPDATE secret_tool_runs
                SET status = 'SUCCEEDED', finding_count = 0, config_hash = ?,
                    engine_version = ?, started_at = clock_timestamp() - INTERVAL '1 second',
                    finished_at = clock_timestamp()
                WHERE tool_run_id = ?
                """, configHash, engineVersion, seed.toolRunId());
        jdbc.update("""
                UPDATE secret_scan_runs
                SET collection_status = ?, detection_status = ?, validation_status = 'SKIPPED'
                WHERE run_id = ?
                """, runCollection, detectionStatus, seed.runId());
        jdbc.update("""
                UPDATE secret_case_revalidations SET runtime_fingerprint_version = ?
                WHERE run_id = ?
                """, fingerprintVersion, seed.runId());
    }

    private void assertOutcome(String expectedResult, String expectedFailure,
                               String expectedPresence, String expectedRun) {
        var result = jdbc.queryForMap("""
                SELECT status, failure_code, finished_at FROM secret_case_revalidations
                WHERE run_id = ?
                """, seed.runId());
        assertThat(result).containsEntry("status", expectedResult)
                .containsEntry("failure_code", expectedFailure);
        assertThat(result.get("finished_at")).isNotNull();
        assertThat(jdbc.queryForObject("""
                SELECT presence_status FROM secret_occurrences WHERE occurrence_id = ?
                """, String.class, seed.occurrenceId())).isEqualTo(expectedPresence);
        assertThat(jdbc.queryForObject("""
                SELECT result_status FROM secret_scan_runs WHERE run_id = ?
                """, String.class, seed.runId())).isEqualTo(expectedRun);
    }

    private Seed seed() {
        long userId = jdbc.queryForObject("""
                INSERT INTO dashboard_users (login_id, password_hash, display_name)
                VALUES ('revalidation-test', 'unused-test-hash', 'Revalidation Test')
                RETURNING user_id
                """, Long.class);
        long connectionId = jdbc.queryForObject("""
                INSERT INTO secret_connections
                    (provider, display_name, auth_ref, status, scope_version)
                VALUES ('GITHUB', 'Synthetic test', 'test-reference', 'ACTIVE', 1)
                RETURNING connection_id
                """, Long.class);
        long scopeId = jdbc.queryForObject("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref, enabled,
                     history_limit, response_origin, response_origin_set_by_user_id,
                     response_origin_set_at)
                VALUES (?, 'fixture', 1, 'GITHUB_REPOSITORY_FILES',
                        'github://Logssey/test-find-key/develop/fixtures/', TRUE,
                        'CURRENT_COMMIT_ONLY', 'TEST', ?, clock_timestamp())
                RETURNING scope_id
                """, Long.class, connectionId, userId);
        long credentialId = jdbc.queryForObject("""
                INSERT INTO secret_credential_sets
                    (issuer, credential_type, component_state, fingerprint,
                     fingerprint_key_version, masked_label, first_seen_at, last_seen_at)
                VALUES ('GITHUB', 'GITHUB_CLASSIC_PAT', 'CONFIRMED',
                        decode(md5(random()::text), 'hex'), 'hmac-v1', '***',
                        clock_timestamp(), clock_timestamp())
                RETURNING credential_set_id
                """, Long.class);
        long occurrenceId = jdbc.queryForObject("""
                INSERT INTO secret_occurrences
                    (credential_set_id, connection_id, scope_id, source_object_ref, location_key,
                     environment, exposure_status, exposure_range, presence_status,
                     first_seen_at, last_seen_at)
                VALUES (?, ?, ?, 'repo/fixture.txt', 'L1', 'UNKNOWN', 'ABNORMAL',
                        'UNKNOWN', 'PRESENT', clock_timestamp(), clock_timestamp())
                RETURNING occurrence_id
                """, Long.class, credentialId, connectionId, scopeId);
        long caseId = jdbc.queryForObject("""
                INSERT INTO secret_response_cases
                    (credential_set_id, opening_occurrence_id, opened_by_user_id,
                     opening_reason, case_origin, action_status, version)
                VALUES (?, ?, ?, 'ASSESSED_EXPOSURE', 'TEST', 'REVALIDATION_PENDING', 2)
                RETURNING case_id
                """, Long.class, credentialId, occurrenceId, userId);
        jdbc.update("""
                INSERT INTO secret_case_occurrences
                    (case_id, occurrence_id, credential_set_id, response_status)
                VALUES (?, ?, ?, 'REVALIDATION_PENDING')
                """, caseId, occurrenceId, credentialId);
        long actionId = jdbc.queryForObject("""
                INSERT INTO secret_action_records
                    (case_id, occurrence_id, action_type, performed_at,
                     recorded_by_user_id, evidence_ref, case_version)
                VALUES (?, ?, 'ROTATED', clock_timestamp() - INTERVAL '1 hour',
                        ?, 'TICKET:SEC-1', 1)
                RETURNING action_id
                """, Long.class, caseId, occurrenceId, userId);
        long jobId = jdbc.queryForObject("""
                INSERT INTO secret_jobs
                    (kind, connection_id, scheduled_at, available_at,
                     attempt_no, max_attempts, status)
                VALUES ('REVALIDATE', ?, clock_timestamp(),
                        clock_timestamp() - INTERVAL '1 second', 0, 1, 'PENDING')
                RETURNING job_id
                """, Long.class, connectionId);
        long runId = jdbc.queryForObject("""
                INSERT INTO secret_scan_runs
                    (job_id, connection_id, trigger_type, scope_version,
                     scheduled_at, requested_at, collection_status,
                     detection_status, validation_status, result_status)
                VALUES (?, ?, 'REVALIDATION', 1, clock_timestamp(), clock_timestamp(),
                        'PENDING', 'PENDING', 'PENDING', 'PENDING')
                RETURNING run_id
                """, Long.class, jobId, connectionId);
        long runScopeId = jdbc.queryForObject("""
                INSERT INTO secret_run_scopes (run_id, scope_id, collection_status)
                VALUES (?, ?, 'PENDING') RETURNING run_scope_id
                """, Long.class, runId, scopeId);
        long toolRunId = jdbc.queryForObject("""
                INSERT INTO secret_tool_runs
                    (run_scope_id, engine, engine_version, config_hash, status)
                VALUES (?, 'GITLEAKS', 'gitleaks-v1', 'config-v1', 'PENDING')
                RETURNING tool_run_id
                """, Long.class, runScopeId);
        jdbc.update("""
                INSERT INTO secret_case_revalidations
                    (case_id, occurrence_id, action_id, connection_id, scope_id, job_id,
                     run_id, requested_by_user_id, idempotency_digest,
                     baseline_config_hash, baseline_engine_version,
                     baseline_fingerprint_version, case_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'test-idempotency',
                        'config-v1', 'gitleaks-v1', 'hmac-v1', 2)
                """, caseId, occurrenceId, actionId, connectionId, scopeId, jobId, runId, userId);
        jdbc.update("""
          UPDATE secret_case_occurrences SET last_material_action_at=(SELECT performed_at FROM secret_action_records WHERE action_id=?),actions_completed_at=clock_timestamp()-INTERVAL '1 minute'
          WHERE case_id=? AND occurrence_id=?
          """,actionId,caseId,occurrenceId);
        jdbc.update("""
          UPDATE secret_case_revalidations v SET scope_revision=1,scope_origin_version=0,action_cycle=1,occurrence_version=0,
            last_material_action_at=co.last_material_action_at,actions_completed_at=co.actions_completed_at,
            baseline_identity=(SELECT fingerprint FROM secret_credential_sets WHERE credential_set_id=?)
          FROM secret_case_occurrences co WHERE v.run_id=? AND co.case_id=v.case_id AND co.occurrence_id=v.occurrence_id
          """,credentialId,runId);
        return new Seed(connectionId, occurrenceId, jobId, runId, runScopeId, toolRunId);
    }

    private record Seed(long connectionId, long occurrenceId, long jobId, long runId,
                        long runScopeId, long toolRunId) {
    }
}
