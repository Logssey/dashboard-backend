package com.logssey.secretworker.permission;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.logssey.secret.aws.SecretAwsSourceCredentials;
import com.logssey.secret.permission.core.SecretPermissionContext;
import com.logssey.secretworker.SecretJobProperties;
import java.time.*;
import java.util.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import tools.jackson.databind.json.JsonMapper;

class PermissionAssistanceExecutorTest {
    static final com.logssey.secret.testing.SecretTestPostgres DB=new com.logssey.secret.testing.SecretTestPostgres();static JdbcTemplate jdbc;static DataSourceTransactionManager tm;
    PermissionAssistanceExecutor executor;long occurrence,identity,sourceAttempt;
    @BeforeAll static void db(){DB.start();var ds=new DriverManagerDataSource(DB.getJdbcUrl(),DB.getUsername(),DB.getPassword());jdbc=new JdbcTemplate(ds);tm=new DataSourceTransactionManager(ds);Flyway.configure().dataSource(ds).load().migrate();}
    @AfterAll static void stop(){DB.stop();}
    @BeforeEach void fixture(){
        jdbc.execute("TRUNCATE dashboard_users,secret_connections RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO dashboard_users(login_id,password_hash,display_name,role) VALUES('security','hash','Security','ADMIN')");
        jdbc.update("INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version,validation_enabled,validation_profile_version) VALUES('GITHUB','Approved source','fixture-app','ACTIVE',1,true,'fixture')");
        jdbc.update("INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,enabled,response_origin,response_origin_set_by_user_id,response_origin_set_at,validation_approved,validation_profile_version,validation_approved_by_user_id,validation_approved_at) VALUES(1,'source',1,'GITHUB_REPOSITORY_FILES','github://Sample/repository/main/src/',true,'PRODUCTION',1,now(),true,'fixture',1,now())");
        jdbc.update("INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source) VALUES(1,'SECURITY',1,1,'MANUAL')");
        jdbc.update("INSERT INTO secret_credential_sets(issuer,credential_type,component_state,fingerprint,fingerprint_key_version,first_seen_at,last_seen_at) VALUES('GITHUB','GITHUB_CLASSIC_PAT','CONFIRMED',decode(repeat('01',32),'hex'),'fixture',now(),now())");
        occurrence=jdbc.queryForObject("INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at) VALUES(1,1,1,'protected','L1','UNKNOWN','UNKNOWN','UNKNOWN','PRESENT',now(),now()) RETURNING occurrence_id",Long.class);
        long job=jdbc.queryForObject("INSERT INTO secret_jobs(kind,connection_id,scheduled_at,available_at,attempt_no,max_attempts,status,finished_at) VALUES('FULL_SCAN',1,now(),now(),1,3,'SUCCEEDED',now()) RETURNING job_id",Long.class);
        long run=jdbc.queryForObject("INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,collection_status,detection_status,validation_status,result_status,finished_at) VALUES(?,1,'MANUAL',1,now(),now(),'SUCCEEDED','SUCCEEDED','SUCCEEDED','SUCCEEDED',now()) RETURNING run_id",Long.class,job);
        long scope=jdbc.queryForObject("INSERT INTO secret_run_scopes(run_id,scope_id,scope_revision,collection_status) VALUES(?,1,1,'SUCCEEDED') RETURNING run_scope_id",Long.class,run);
        long tool=jdbc.queryForObject("INSERT INTO secret_tool_runs(run_scope_id,engine,engine_version,config_hash,status) VALUES(?,'GITLEAKS','fixture','fixture','SUCCEEDED') RETURNING tool_run_id",Long.class,scope);
        long finding=jdbc.queryForObject("INSERT INTO secret_findings(occurrence_id,run_id,tool_run_id,finding_key,rule_id,rule_version,detected_at) VALUES(?,?,?,?,'fixture','1',now()) RETURNING finding_id",Long.class,occurrence,run,tool,UUID.randomUUID().toString());
        sourceAttempt=jdbc.queryForObject("""
INSERT INTO secret_validation_attempts(credential_set_id,run_id,job_id,validator_id,validator_version,endpoint_class,requested_at,completed_at,provider_checked_at,result,reason_code,request_sent_at,scope_id,occurrence_id,source_finding_id,credential_revision,scope_revision,validation_revision,validation_approval_revision,validation_profile_version,action_context_digest,dedup_key,cycle_key,attempt_no,reservation_generation,reservation_token,current_eligible,evidence_version)
VALUES(1,?,?,'FIXTURE_IDENTITY','1','FIXTURE_IDENTITY',now()-interval '2 hours',now()-interval '2 hours',now()-interval '2 hours','VALID','AUTHENTICATED',now()-interval '2 hours',1,?,?,1,1,1,1,'fixture',decode(repeat('02',32),'hex'),decode(repeat('03',32),'hex'),?,1,1,gen_random_uuid(),true,1) RETURNING attempt_id
""",Long.class,run,job,occurrence,finding,UUID.randomUUID().toString());
        identity=jdbc.queryForObject("INSERT INTO secret_credential_identities(validation_attempt_id,occurrence_id,credential_set_id,credential_revision,scope_revision,provider,principal_type,principal_ref,principal_id,safe_claims,observed_at,expires_at) SELECT attempt_id,occurrence_id,1,1,1,'GITHUB','GITHUB_USER','github-user:123','123','{\"tokenKind\":\"CLASSIC\",\"scopes\":[\"repo\"],\"scopesComplete\":true}',provider_checked_at,provider_checked_at+interval '6 hours' FROM secret_validation_attempts WHERE attempt_id=? RETURNING identity_id",Long.class,sourceAttempt);
        var props=new SecretJobProperties(true,Duration.ofSeconds(30),Duration.ofSeconds(30),10,Duration.ofSeconds(1),Duration.ofSeconds(30));
        @SuppressWarnings("unchecked")ObjectProvider<SecretAwsSourceCredentials> sources=mock(ObjectProvider.class);executor=new PermissionAssistanceExecutor(jdbc,tm,props,sources);
    }
    @Test void githubReuseKeepsActualObservationTimeAndDoesNotRefreshProofOrChangeGrade(){
        long request=request();var lease=executor.claim().orElseThrow();assertThat(executor.execute(lease)).isTrue();
        var observation=jdbc.queryForMap("SELECT * FROM secret_permission_observations WHERE request_id=?",request);
        var actual=jdbc.queryForObject("SELECT provider_checked_at FROM secret_validation_attempts WHERE attempt_id=?",OffsetDateTime.class,sourceAttempt);
        assertThat(SecretPermissionContext.time(observation.get("observed_at"))).isEqualTo(actual);
        assertThat(SecretPermissionContext.time(observation.get("expires_at"))).isBeforeOrEqualTo(actual.plusHours(6));
        assertThat(observation.get("safe_facts").toString()).contains("RECENT_VALIDATION_METADATA","PARTIAL").doesNotContain("github-user:123","fixture-app");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_risk_evidence",Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_severity_assessments",Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_scan_runs r JOIN secret_jobs j USING(job_id) WHERE j.kind='ENRICH'",Long.class)).isZero();
    }
    @Test void changedScopeOrRevokedRequesterCannotPublishObservation(){
        request();var lease=executor.claim().orElseThrow();jdbc.update("UPDATE secret_role_grants SET revoked_at=now() WHERE user_id=1");
        assertThat(executor.execute(lease)).isFalse();assertThat(jdbc.queryForObject("SELECT status FROM secret_jobs WHERE job_id=?",String.class,lease.jobId())).isEqualTo("CANCELLED");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_permission_observations",Long.class)).isZero();
    }
    @Test void permissionRecoveryLeavesExpiredUsageJobsForTheirOwnExecutor(){
        var token=UUID.randomUUID();
        long usageJob=jdbc.queryForObject("""
INSERT INTO secret_jobs(kind,purpose,connection_id,target_occurrence_id,requested_by_user_id,
scheduled_at,available_at,attempt_no,max_attempts,status,lease_owner,lease_token,lease_generation,lease_until)
VALUES('ENRICH','USAGE_OBSERVATION',1,?,1,clock_timestamp(),clock_timestamp(),1,3,'LEASED',?,?,1,clock_timestamp()-interval '1 second') RETURNING job_id
""",Long.class,occurrence,token.toString(),token);
        assertThat(executor.claim()).isEmpty();
        var untouched=jdbc.queryForMap("SELECT status,attempt_no,lease_token,last_error_code FROM secret_jobs WHERE job_id=?",usageJob);
        assertThat(untouched.get("status")).isEqualTo("LEASED");
        assertThat(untouched.get("attempt_no")).isEqualTo(1);
        assertThat(untouched.get("lease_token")).isEqualTo(token);
        assertThat(untouched.get("last_error_code")).isNull();
    }
    @Test void anExpiredLeaseCannotPublishAndRecoveryUsesANewGeneration(){
        request();var first=executor.claim().orElseThrow();jdbc.update("UPDATE secret_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE job_id=?",first.jobId());
        assertThat(executor.execute(first)).isFalse();var second=executor.claim().orElseThrow();assertThat(second.generation()).isGreaterThan(first.generation());assertThat(second.token()).isNotEqualTo(first.token());
        assertThat(executor.execute(first)).isFalse();assertThat(executor.execute(second)).isTrue();assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_permission_observations",Long.class)).isEqualTo(1L);
    }
    private long request(){var c=new SecretPermissionContext(jdbc).read(occurrence);var baseline=Map.of("contextVersion",SecretPermissionContext.version(c),"sourceContextVersion",SecretPermissionContext.sourceVersion(c),"collectorScopeVersion",1,"collectorAuthRef","fixture-app","collectorScopeId",1,"collectorScopeRevision",1,"collectorApprovedRef","github://Sample/repository/main/src/");var encoded=new JsonMapper().writeValueAsString(baseline);long job=jdbc.queryForObject("INSERT INTO secret_jobs(kind,purpose,connection_id,target_occurrence_id,requested_by_user_id,expected_context,scheduled_at,available_at,attempt_no,max_attempts,status) VALUES('ENRICH','PERMISSION_ASSISTANCE',1,?,1,?::jsonb,clock_timestamp(),clock_timestamp(),0,3,'PENDING') RETURNING job_id",Long.class,occurrence,encoded);return jdbc.queryForObject("INSERT INTO secret_permission_requests(job_id,occurrence_id,identity_id,collector_connection_id,requested_by_user_id,context_version,baseline) VALUES(?,?,?,1,1,?,?::jsonb) RETURNING request_id",Long.class,job,occurrence,identity,SecretPermissionContext.version(c),encoded);}
}
