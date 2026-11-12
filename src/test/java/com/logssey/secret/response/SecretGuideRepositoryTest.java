package com.logssey.secret.response;

import static org.assertj.core.api.Assertions.assertThat;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

class SecretGuideRepositoryTest {
    private static final PostgreSQLContainer POSTGRES = new com.logssey.secret.testing.SecretTestPostgres();
    private static JdbcTemplate jdbc;
    private SecretGuideRepository repository;
    private long caseId;
    private long runId;
    private long jobId;
    private long credentialId;
    private long occurrenceId;

    @BeforeAll static void startDatabase() {
        POSTGRES.start();
        var source = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(source).load().migrate();
        jdbc = new JdbcTemplate(source);
    }
    @AfterAll static void stopDatabase() { POSTGRES.stop(); }

    @BeforeEach void prepare() {
        jdbc.execute("TRUNCATE secret_connections,dashboard_users RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO dashboard_users(login_id,password_hash,display_name,role) VALUES('guide-facts','test-hash','Guide facts','ADMIN')");
        jdbc.update("""
                INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version,validation_enabled,validation_profile_version)
                VALUES('GITHUB','Guide connection','test-only-ref','ACTIVE',1,true,'credential-validation-v1')
                """);
        jdbc.update("""
                INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,enabled,
                 history_limit,response_origin,response_origin_set_by_user_id,response_origin_set_at,
                 validation_approved,validation_profile_version,validation_approved_by_user_id,validation_approved_at)
                VALUES(1,'guide',1,'GITHUB_REPOSITORY_FILES','github://Other/guide/main/src/',true,
                 'CURRENT_COMMIT_ONLY','TEST',1,clock_timestamp(),true,'credential-validation-v1',1,clock_timestamp())
                """);
        credentialId = jdbc.queryForObject("""
                INSERT INTO secret_credential_sets(issuer,credential_type,component_state,fingerprint,fingerprint_key_version,first_seen_at,last_seen_at)
                VALUES('GITHUB','GITHUB_CLASSIC_PAT','CONFIRMED',sha256(convert_to('guide-facts','UTF8')),'test-v1',clock_timestamp(),clock_timestamp()) RETURNING credential_set_id
                """, Long.class);
        occurrenceId = occurrence("first");
        caseId = jdbc.queryForObject("""
                INSERT INTO secret_response_cases(credential_set_id,opening_occurrence_id,opened_by_user_id,opening_reason,case_origin)
                VALUES(?,?,1,'ASSESSED_EXPOSURE','TEST') RETURNING case_id
                """, Long.class, credentialId, occurrenceId);
        jdbc.update("INSERT INTO secret_case_occurrences(case_id,occurrence_id,credential_set_id) VALUES(?,?,?)", caseId, occurrenceId, credentialId);
        jobId = jdbc.queryForObject("""
                INSERT INTO secret_jobs(kind,connection_id,scheduled_at,available_at,attempt_no,max_attempts,status,finished_at)
                VALUES('FULL_SCAN',1,clock_timestamp(),clock_timestamp(),1,3,'SUCCEEDED',clock_timestamp()) RETURNING job_id
                """, Long.class);
        runId = jdbc.queryForObject("""
                INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,
                 collection_status,detection_status,validation_status,result_status)
                VALUES(?,1,'MANUAL',1,clock_timestamp(),clock_timestamp(),'SUCCEEDED','SUCCEEDED','SUCCEEDED','SUCCEEDED') RETURNING run_id
                """, Long.class, jobId);
        long runScope = jdbc.queryForObject("""
                INSERT INTO secret_run_scopes(run_id,scope_id,collection_status,object_count,finished_at)
                VALUES(?,1,'SUCCEEDED',1,clock_timestamp()) RETURNING run_scope_id
                """, Long.class, runId);
        long tool = jdbc.queryForObject("""
                INSERT INTO secret_tool_runs(run_scope_id,engine,engine_version,config_hash,status,finding_count,finished_at)
                VALUES(?,'GITLEAKS','8.30.1','test-hash','SUCCEEDED',1,clock_timestamp()) RETURNING tool_run_id
                """, Long.class, runScope);
        jdbc.update("""
                INSERT INTO secret_findings(occurrence_id,run_id,tool_run_id,finding_key,rule_id,rule_version,detected_at)
                VALUES(?,?,?,'guide-finding','github-pat','1',clock_timestamp())
                """, occurrenceId, runId, tool);
        repository = new SecretGuideRepository(jdbc);
    }

    @Test void onlyCurrentEligibleObservationsBecomeContextFacts() {
        long attempt = observation("INVALID", 0);
        assertThat(contextStatus()).isEqualTo("INVALID");
        jdbc.update("UPDATE secret_validation_attempts SET current_eligible=false,ineligible_reason_code='APPROVAL_CHANGED' WHERE attempt_id=?", attempt);
        assertThat(contextStatus()).isEqualTo("UNCHECKED");
    }

    @Test void staleConclusiveResultsBecomeUnknownAndLegacyHistoryCannotOverrideCurrentFacts() {
        long attempt = observation("VALID", 7);
        assertThat(contextStatus()).isEqualTo("UNKNOWN");
        jdbc.update("UPDATE secret_validation_attempts SET current_eligible=false,ineligible_reason_code='APPROVAL_CHANGED' WHERE attempt_id=?", attempt);
        observation("INVALID", 0);
        jdbc.update("""
                INSERT INTO secret_validation_attempts(credential_set_id,run_id,job_id,validator_id,validator_version,
                 endpoint_class,requested_at,completed_at,provider_checked_at,result,reason_code)
                VALUES(?,?,?,'GITHUB_GET_AUTHENTICATED_USER','legacy','GITHUB_USER',clock_timestamp(),clock_timestamp()+interval '1 second',clock_timestamp(),'VALID','AUTHENTICATED')
                """, credentialId, runId, jobId);
        assertThat(contextStatus()).isEqualTo("INVALID");
    }

    @Test void latestRelevantValidationMatchesCaseHeadlineWhenAnotherLocationHasNoAttempt() {
        observation("VALID", 0);
        long other = occurrence("second");
        jdbc.update("INSERT INTO secret_case_occurrences(case_id,occurrence_id,credential_set_id) VALUES(?,?,?)", caseId, other, credentialId);
        assertThat(contextStatus()).isEqualTo("VALID");
        jdbc.update("""
                INSERT INTO secret_action_records(case_id,occurrence_id,action_type,performed_at,
                 recorded_by_user_id,evidence_ref,case_version)
                VALUES(?,?,'REVOKED',clock_timestamp(),1,'TICKET:GUIDE-1',1)
                """, caseId, other);
        assertThat(contextStatus()).isEqualTo("UNCHECKED");
    }

    @Test void resolvedLocationsDoNotSupplyValidationForAnUnresolvedLocation() {
        observation("VALID", 0);
        jdbc.update("UPDATE secret_case_occurrences SET response_status='RESOLVED' WHERE case_id=? AND occurrence_id=?", caseId, occurrenceId);
        long other = occurrence("unresolved");
        jdbc.update("INSERT INTO secret_case_occurrences(case_id,occurrence_id,credential_set_id) VALUES(?,?,?)", caseId, other, credentialId);
        assertThat(contextStatus()).isEqualTo("UNCHECKED");
    }

    private String contextStatus() { return repository.currentCase(caseId).orElseThrow().safeContext().validationStatus(); }

    private long occurrence(String marker) {
        return jdbc.queryForObject("""
                INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,
                 environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at)
                VALUES(?,1,1,?,'L1','UNKNOWN','ABNORMAL','UNKNOWN','PRESENT',clock_timestamp(),clock_timestamp()) RETURNING occurrence_id
                """, Long.class, credentialId, "private/" + marker);
    }

    private long observation(String result, int ageHours) {
        return jdbc.queryForObject("""
                WITH stamp AS (SELECT clock_timestamp()-(?*interval '1 hour') AS at)
                INSERT INTO secret_validation_attempts(evidence_version,credential_set_id,run_id,job_id,validator_id,
                 validator_version,endpoint_class,requested_at,completed_at,provider_checked_at,result,reason_code,
                 attempt_state,request_sent_at,scope_id,occurrence_id,source_object_version_digest,credential_revision,
                 scope_revision,validation_revision,validation_approval_revision,validation_profile_version,
                 action_context_digest,dedup_key,cycle_key,attempt_no,reservation_generation,reservation_token,current_eligible,ineligible_reason_code)
                SELECT 1,?,?,?,'GITHUB_GET_AUTHENTICATED_USER','v1','GITHUB_USER',at-interval '2 seconds',at+interval '1 second',at,
                 ?,'AUTHENTICATED','COMPLETED',at-interval '1 second',1,?,decode(repeat('11',32),'hex'),1,1,1,1,'credential-validation-v1',
                 decode(repeat('22',32),'hex'),decode(repeat('33',32),'hex'),'guide-facts',1,1,'11111111-1111-1111-1111-111111111111'::uuid,true,NULL FROM stamp
                RETURNING attempt_id
                """, Long.class, ageHours, credentialId, runId, jobId, result, occurrenceId);
    }
}
