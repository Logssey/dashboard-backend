package com.logssey.secret.connection;

import java.time.OffsetDateTime;
import java.util.*;
import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.run.SecretScanFactsRepository;
import com.logssey.common.error.ApiException;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;
import static org.assertj.core.api.Assertions.*;

class SecretScanCoverageIntegrationTest {
    static final PostgreSQLContainer POSTGRES=new PostgreSQLContainer("postgres:18.6");
    static JdbcTemplate jdbc;
    SecretCoverageService service;SecretScanFactsRepository facts;
    @BeforeAll static void start(){POSTGRES.start();var ds=new DriverManagerDataSource(POSTGRES.getJdbcUrl(),POSTGRES.getUsername(),POSTGRES.getPassword());
        Flyway.configure().dataSource(ds).load().migrate();jdbc=new JdbcTemplate(ds);}
    @AfterAll static void stop(){POSTGRES.stop();}
    @BeforeEach void reset(){jdbc.execute("TRUNCATE secret_connections,dashboard_users RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO dashboard_users(login_id,password_hash,display_name,role) VALUES('operator','unused','Operator','ADMIN'),('stranger','unused','Other','ADMIN')");
        service=new SecretCoverageService(jdbc,new SecretAccessService(jdbc));facts=new SecretScanFactsRepository(jdbc);}

    @Test void operatorsSeeTheRegisteredTargetWithoutRawAuthenticationOrApprovalUris(){
        long c=connection(),s=scope(c,"GITHUB_REPOSITORY_FILES");
        jdbc.update("UPDATE secret_connection_scopes SET approved_ref='github://Logssey/test-find-key/main/fixtures/' WHERE scope_id=?",s);
        var row=items(service.scopes("operator",c,"ALL","ALL",false,0,20)).getFirst();
        assertThat(row.get("safeDisplayAlias")).isEqualTo("Logssey/test-find-key · main · fixtures/");
        var connection=items(service.connections("operator","ALL","ALL",0,20)).getFirst();
        assertThat(connection.get("targetSummary").toString()).contains("Logssey/test-find-key");
        assertThat(connection.toString()).doesNotContain("github://","secret-value","approved_ref");
    }
    @Test void exclusiveOutcomesCountSuccessfulSeparatelyFromFinishedAndUseStageEvidence(){
        long c=connection();List<Long> scopes=new ArrayList<>();for(int i=0;i<12;i++)scopes.add(scope(c,"GITHUB_REPOSITORY_FILES"));
        long run=run(c,"SUCCEEDED");
        for(int i=0;i<12;i++)outcome(run,scopes.get(i),i<8?"SUCCEEDED":"FAILED",i==7?"PARTIAL":"SKIPPED",i==7);
        var summary=facts.runCoverage(run);
        assertThat(summary.finishedScopeCount()).isEqualTo(12);assertThat(summary.successfulScopeCount()).isEqualTo(7);
        assertThat(summary.gapScopeCount()).isEqualTo(5);assertThat(summary.unverifiedScopeCount()).isEqualTo(5);assertThat(summary.scopeStatusCounts()).containsEntry("PARTIAL",1L).containsEntry("FAILED",4L);
        assertThat(summary.scopeStatusCounts().values().stream().mapToLong(Long::longValue).sum()).isEqualTo(12);
        assertThat(summary.coverageComplete()).isFalse();assertThat(summary.findingCount()).isNull();assertThat(summary.newCredentialCount()).isNull();
    }

    @Test void latestFailureRetainsSameRevisionLastSuccessWithoutLeakingSourceNames(){
        long c=connection(),scope=scope(c,"GITHUB_REPOSITORY_FILES");long success=run(c,"SUCCEEDED");outcome(success,scope,"SUCCEEDED","SKIPPED",false);
        long failed=run(c,"FAILED");outcome(failed,scope,"FAILED","SKIPPED",false);
        var row=items(service.scopes("operator",c,"ALL","ALL",false,0,20)).getFirst();var cov=(Map<?,?>)row.get("coverage");
        assertThat(cov.get("lastAttempt").toString()).contains("runId="+failed);
        assertThat(cov.get("lastSuccessfulScan").toString()).contains("runId="+success);
        assertThat(cov.get("gapReasonCodes").toString()).contains("LAST_ATTEMPT_INCOMPLETE");
        assertThat(row.toString()).doesNotContain("private-repo","secret-value","aws://","approved_ref");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_occurrences",Long.class)).isZero();
        assertThat(items(service.connections("operator","ALL","ALL",0,20)).getFirst().get("lastSuccessfulFullScan").toString()).contains("runId="+success);
    }

    @Test void changedRevisionCannotReusePreviousSuccessAndRevalidationIsNotFullCoverage(){
        long c=connection(),scope=scope(c,"GITHUB_REPOSITORY_FILES");long old=run(c,"SUCCEEDED");outcome(old,scope,"SUCCEEDED","SKIPPED",false);
        jdbc.update("UPDATE secret_connection_scopes SET revision=2 WHERE scope_id=?",scope);
        var cov=(Map<?,?>)items(service.scopes("operator",c,"ALL","ALL",false,0,20)).getFirst().get("coverage");
        assertThat(cov.get("lastSuccessfulScan")).isNull();assertThat(cov.get("gapReasonCodes").toString()).contains("REVISION_UNCHECKED");
        long rv=run(c,"SUCCEEDED");outcome(rv,scope,"SUCCEEDED","SKIPPED",false);
        jdbc.update("UPDATE secret_jobs SET kind='REVALIDATE',purpose='LOCATION_RECHECK' WHERE job_id=(SELECT job_id FROM secret_scan_runs WHERE run_id=?)",rv);
        cov=(Map<?,?>)items(service.scopes("operator",c,"ALL","ALL",false,0,20)).getFirst().get("coverage");assertThat(cov.get("lastSuccessfulScan")).isNull();
    }

    @Test void legacyFactsAreNotGuessedAndMetadataDoesNotClaimValueInspection(){
        long c=connection(),scope=scope(c,"IAM_ACCESS_KEY_METADATA");long run=run(c,"SUCCEEDED");outcome(run,scope,"SUCCEEDED","SKIPPED",false);
        jdbc.queryForList("SELECT secret_record_scope_evidence(run_scope_id,false) FROM secret_run_scopes WHERE run_id=?",run);
        var details=facts.scopes(run).getFirst();assertThat(details.detection().status()).isEqualTo("SKIPPED");
        assertThat(details.detection().reasonCode()).isEqualTo("NOT_APPLICABLE_METADATA");assertThat(facts.runCoverage(run).findingCount()).isNull();
        jdbc.update("UPDATE secret_run_scopes SET evidence_version=NULL,scope_revision=NULL WHERE run_id=?",run);
        var summary=facts.runCoverage(run);assertThat(summary.successfulScopeCount()).isNull();assertThat(summary.gapScopeCount()).isNull();
        assertThat(summary.aggregationStatus()).isEqualTo("LEGACY_UNAVAILABLE");assertThat(summary.unverifiedScopeCount()).isEqualTo(1);
    }

    @Test void queuedRetryDoesNotHideEarlierGapAndPermissionsBoundEveryList(){
        long c=connection(),scope=scope(c,"GITHUB_REPOSITORY_FILES");long failed=run(c,"FAILED");outcome(failed,scope,"FAILED","SKIPPED",false);
        run(c,"PENDING");var gap=items(service.gaps("operator","ALL","ALL",null,null,0,20));assertThat(gap).hasSize(1);
        assertThat(((Map<?,?>)gap.getFirst().get("coverage")).get("gapReasonCodes").toString()).contains("LAST_ATTEMPT_INCOMPLETE");
        assertThatThrownBy(()->service.connections("stranger","ALL","ALL",0,20)).isInstanceOf(ApiException.class);
        assertThatThrownBy(()->service.scopes("stranger",c,"ALL","ALL",false,0,20)).isInstanceOf(ApiException.class);
        assertThatThrownBy(()->service.gaps("operator","ALL","ALL",null,"not-a-snapshot",0,20)).isInstanceOf(ApiException.class);
    }

    @Test void probeHistoryIsSeparateFromRealReadAndCannotModifyCollectionSuccess(){
        long c=connection();scope(c,"GITHUB_REPOSITORY_FILES");var repo=new SecretConnectionTestRepository(jdbc);
        repo.recordProbe(c,"operator",new SecretConnectionTestResponse(c,"GITHUB","CONNECTED",null,OffsetDateTime.now()));
        var row=items(service.connections("operator","ALL","ALL",0,20)).getFirst();
        assertThat(row.get("latestProbe").toString()).contains("IDENTITY_OR_INSTALLATION","CONNECTED");
        assertThat(row.get("lastSuccessfulFullScan")).isNull();assertThat(row.get("lastFullScanAttempt")).isNull();
        assertThat(jdbc.queryForObject("SELECT last_collection_success_at FROM secret_connections WHERE connection_id=?",OffsetDateTime.class,c)).isNull();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_scan_runs",Long.class)).isZero();
    }

    @Test void aReplacementRevisionDoesNotHideHistoricalInspectionOrPretendItWasCurrent(){
        long c=connection(),oldScope=scope(c,"GITHUB_REPOSITORY_FILES"),oldRun=run(c,"SUCCEEDED");outcome(oldRun,oldScope,"SUCCEEDED","SKIPPED",false);
        jdbc.update("UPDATE secret_connection_scopes SET enabled=false WHERE scope_id=?",oldScope);
        jdbc.update("""
            INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,enabled)
            SELECT connection_id,scope_key,revision+1,content_type,approved_ref,true FROM secret_connection_scopes WHERE scope_id=?
            """,oldScope);
        var rows=items(service.scopes("operator",c,"ALL","ALL",false,0,20));assertThat(rows).hasSize(1);
        var cov=(Map<?,?>)rows.getFirst().get("coverage");assertThat(cov.get("lastSuccessfulScan")).isNull();
        assertThat(cov.get("gapReasonCodes").toString()).contains("REVISION_UNCHECKED");
        assertThat(rows.getFirst().toString()).doesNotContain("github://","private-repo","secret-value");
    }

    @Test void scheduleAdvancementWhileQueuedDoesNotHideAnOverdueLastSuccess(){
        long c=connection(),scope=scope(c,"GITHUB_REPOSITORY_FILES"),run=run(c,"SUCCEEDED");outcome(run,scope,"SUCCEEDED","SKIPPED",false);
        jdbc.update("UPDATE secret_run_scopes SET finished_at=now()-interval '12 hours' WHERE run_id=?",run);
        jdbc.update("UPDATE secret_connections SET next_due_at=now()+interval '6 hours' WHERE connection_id=?",c);
        var cov=(Map<?,?>)items(service.scopes("operator",c,"ALL","ALL",false,0,20)).getFirst().get("coverage");
        assertThat(cov.get("freshness")).isEqualTo("OVERDUE");assertThat(cov.get("gapReasonCodes").toString()).contains("OVERDUE");
    }

    @Test void assignedRemediatorCanReadOnlyOwnScopeCoverageWithoutManagementAuthority(){
        long c=connection(),scope=scope(c,"GITHUB_REPOSITORY_FILES"),run=run(c,"SUCCEEDED");outcome(run,scope,"SUCCEEDED","SKIPPED",false);
        long key=jdbc.queryForObject("""
            INSERT INTO secret_credential_sets(issuer,credential_type,component_state,first_seen_at,last_seen_at)
            VALUES('GITHUB','GITHUB_PAT','METADATA_ONLY',now(),now()) RETURNING credential_set_id
            """,Long.class);
        long occurrence=jdbc.queryForObject("""
            INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,environment,
                exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at)
            VALUES(?,?,?,'private-repo/secret-value','L1','UNKNOWN','UNKNOWN','UNKNOWN','PRESENT',now(),now()) RETURNING occurrence_id
            """,Long.class,key,c,scope);
        assertThatThrownBy(()->service.occurrenceCoverage("operator",occurrence)).isInstanceOf(ApiException.class);
        jdbc.update("INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source) VALUES(2,'REMEDIATOR',?,1,'MANUAL')",c);
        long response=jdbc.queryForObject("""
            INSERT INTO secret_response_cases(credential_set_id,opening_occurrence_id,opened_by_user_id,opening_reason,case_origin,assigned_user_id)
            VALUES(?,?,1,'ASSESSED_EXPOSURE','TEST',2) RETURNING case_id
            """,Long.class,key,occurrence);
        jdbc.update("INSERT INTO secret_case_occurrences(case_id,occurrence_id,credential_set_id,assigned_user_id) VALUES(?,?,?,2)",response,occurrence,key);
        var cov=service.occurrenceCoverage("stranger",occurrence);assertThat(cov.get("scopeId")).isEqualTo(scope);
        assertThat(cov.get("lastSuccessfulScan")).isNotNull();assertThat(cov.toString()).doesNotContain("private-repo","secret-value","credential_set_id");
        assertThatThrownBy(()->service.connections("stranger","ALL","ALL",0,20)).isInstanceOf(ApiException.class);
        jdbc.update("UPDATE secret_role_grants SET revoked_at=now() WHERE user_id=2");
        assertThatThrownBy(()->service.occurrenceCoverage("stranger",occurrence)).isInstanceOf(ApiException.class);
    }

    @Test void runCoverageIsFlattenedWithoutDuplicateProviderOrProtectedSourceFields(){
        long c=connection(),scope=scope(c,"GITHUB_REPOSITORY_FILES"),run=run(c,"SUCCEEDED");outcome(run,scope,"SUCCEEDED","SKIPPED",false);
        var response=new com.logssey.secret.run.SecretRunStatusResponse(run,c,"MANUAL","SUCCEEDED","SUCCEEDED","SUCCEEDED","SKIPPED",
            1,1,0,0,0,3,null,null,null,null,null,facts.scopes(run),facts.runCoverage(run));
        var mapper=tools.jackson.databind.json.JsonMapper.builder().build();
        String json=mapper.writeValueAsString(response);var tree=mapper.readTree(json);
        assertThat(tree.get("successfulScopeCount").asLong()).isEqualTo(1);
        assertThat(tree.get("provider").asString()).isEqualTo("GITHUB");
        assertThat(json.indexOf("\"provider\"")).isEqualTo(json.lastIndexOf("\"provider\""));
        assertThat(tree.has("coverage")).isFalse();assertThat(json).doesNotContain("private-repo","secret-value","approved_ref");
    }

    long connection(){long id=jdbc.queryForObject("INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version,next_due_at) VALUES('GITHUB','private-repo','secret-value','ACTIVE',1,now()+interval '6 hours') RETURNING connection_id",Long.class);
        jdbc.update("INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source) VALUES(1,'OPERATIONS',?,1,'MANUAL')",id);return id;}
    long scope(long c,String type){return jdbc.queryForObject("INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,enabled) VALUES(?,gen_random_uuid()::text,1,?,'github://private-repo/secret-value',true) RETURNING scope_id",Long.class,c,type);}
    long run(long c,String status){long job=jdbc.queryForObject("""
        INSERT INTO secret_jobs(kind,connection_id,scheduled_at,available_at,attempt_no,max_attempts,status,finished_at)
        VALUES('FULL_SCAN',?,clock_timestamp(),now(),0,3,?,CASE WHEN ?='PENDING' THEN NULL ELSE now() END) RETURNING job_id
        """,Long.class,c,status,status);
        long run=jdbc.queryForObject("""
        INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,collection_status,detection_status,validation_status,result_status,finished_at)
        VALUES(?,?,'MANUAL',1,now(),clock_timestamp(),'SUCCEEDED','SUCCEEDED','SKIPPED',?,CASE WHEN ?='PENDING' THEN NULL ELSE now() END) RETURNING run_id
        """,Long.class,job,c,status,status);
        jdbc.update("INSERT INTO secret_run_scopes(run_id,scope_id,collection_status) SELECT ?,scope_id,'PENDING' FROM secret_connection_scopes WHERE connection_id=? AND enabled",run,c);return run;}
    void outcome(long run,long scope,String collection,String validation,boolean required){jdbc.update("""
        UPDATE secret_run_scopes SET collection_status=?,object_count=0,finished_at=clock_timestamp(),
          detection_stage_status='SUCCEEDED',validation_stage_status=?,validation_required=? WHERE run_id=? AND scope_id=?
        """,collection,validation,required,run,scope);}
    @SuppressWarnings("unchecked") static List<Map<String,Object>> items(Map<String,Object> p){return (List<Map<String,Object>>)p.get("items");}
}
