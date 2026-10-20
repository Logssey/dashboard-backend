package com.logssey.secret.query;

import java.util.List;
import java.util.Map;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.json.JsonMapper;
import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.command.SecretCommandExecutor;
import com.logssey.secret.connection.SecretCoverageService;
import com.logssey.secret.lifecycle.SecretLifecycleService;
import com.logssey.secret.response.SecretLocationReadiness;
import com.logssey.secret.response.SecretLocationWorkflow;
import com.logssey.secret.snapshot.SecretReadSnapshots;
import static org.assertj.core.api.Assertions.*;

class RetiredHistoryIntegrationTest {
    static final PostgreSQLContainer DB=new PostgreSQLContainer("postgres:18.6");
    static JdbcTemplate jdbc;static DataSourceTransactionManager manager;static TransactionTemplate tx;
    SecretLocationRepository repository;SecretLocationService service;
    long user,reviewer,connection,scope,key,occurrence,caseId;
    @BeforeAll static void start() {
        DB.start();var ds=new DriverManagerDataSource(DB.getJdbcUrl(),DB.getUsername(),DB.getPassword());
        Flyway.configure().dataSource(ds).load().migrate();jdbc=new JdbcTemplate(ds);manager=new DataSourceTransactionManager(ds);
        tx=new TransactionTemplate(manager);tx.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
    }
    @AfterAll static void stop(){DB.stop();}
    @BeforeEach void setup() {
        jdbc.execute("TRUNCATE dashboard_users,secret_connections,secret_lifecycle_provider_writers,secret_lifecycle_provider_capabilities RESTART IDENTITY CASCADE");
        user=user("security");reviewer=user("reviewer");connection=connection("GITHUB");scope=scope(connection,"PRODUCTION");
        grant(user,connection);jdbc.update("INSERT INTO secret_role_grants(user_id,role,granted_by_user_id,grant_source) VALUES(?,'SECURITY',?,'MANUAL')",reviewer,reviewer);
        key=jdbc.queryForObject("""
            INSERT INTO secret_credential_sets(issuer,credential_type,component_state,fingerprint,fingerprint_key_version,masked_label,first_seen_at,last_seen_at)
            VALUES('AWS','AWS_ACCESS_KEY_PAIR','CONFIRMED',decode(md5(random()::text),'hex'),'test','AWS ••••1234',now(),now()) RETURNING credential_set_id
            """,Long.class);
        occurrence=occurrence(connection,scope,"PROD","ABNORMAL","MISSING");caseId=caseFor(occurrence,"PRODUCTION");
        var access=new SecretAccessService(jdbc);var snapshots=new SecretReadSnapshots(jdbc,JsonMapper.builder().build());
        var commands=new SecretCommandExecutor(jdbc,manager);var readiness=new SecretLocationReadiness(jdbc,access);
        var workflow=new SecretLocationWorkflow(jdbc,access,commands,snapshots,readiness);
        repository=new SecretLocationRepository(jdbc);
        service=new SecretLocationService(repository,snapshots,access,new SecretCoverageService(jdbc,access),readiness,new SecretLifecycleService(jdbc,access,workflow,commands,snapshots));
    }
    @Test void currentProviderRetirementAppearsInNormalInventoryWithItsOwnSubtype() {
        provider(caseId,occurrence,"PRODUCTION","REVOKED");
        assertThat(repository.retiredHistory(rows())).isTrue();
        var result=inventory(filters("ALL","NORMAL_INVENTORY"));
        assertThat(result.get("total")).isEqualTo(1L);
        var item=items(result).getFirst();
        assertThat(item).containsEntry("inventorySubtype","RETIRED_HISTORY").containsEntry("workBucket","NORMAL_INVENTORY")
            .containsEntry("whyHereCode","PROVIDER_RETIREMENT_CONFIRMED");
        assertThat(service.detail("security",key,"PRODUCTION").get("inventorySubtype")).isEqualTo("RETIRED_HISTORY");
        assertThat(item.toString()).doesNotContain("private-path","fingerprint","provider_validator_id");
    }
    @Test void aProviderConfirmedRotationAlsoQualifies() {
        provider(caseId,occurrence,"PRODUCTION","ROTATED");
        assertThat(repository.retiredHistory(rows())).isTrue();
    }
    @Test void aProviderConfirmedEndOfUseIsRetiredHistoryWithoutAnInventedExpiryDate() {
        provider(caseId,occurrence,"PRODUCTION","RETIRED");
        assertThat(repository.retiredHistory(rows())).isTrue();
        var detail=service.detail("security",key,"PRODUCTION");
        assertThat(detail.get("inventorySubtype")).isEqualTo("RETIRED_HISTORY");
        assertThat(detail.get("expiresAt")).isNull();assertThat(detail.get("expiryPolicy")).isEqualTo("UNKNOWN");
    }
    @Test void missingAndAnAuthenticationRejectionNeverBecomeRetirementEvidence() {
        assertThat(repository.retiredHistory(rows())).isFalse();
        validation(occurrence,"INVALID","INVALID_ACCESS_KEY");
        assertThat(rows().getFirst().validity()).isEqualTo("INVALID");
        assertThat(repository.retiredHistory(rows())).isFalse();
        assertThat(inventory(filters("ALL","NORMAL_INVENTORY")).get("total")).isEqualTo(0L);
    }
    @Test void independentlyApprovedManualEvidenceStaysLimitedAndDoesNotQualify() {
        long evidence=jdbc.queryForObject("""
            INSERT INTO secret_credential_lifecycle_evidence(case_id,credential_set_id,source_occurrence_id,origin,kind,
                verification_method,verification_level,evidence_ref,performed_at,observed_at,submitted_by_user_id)
            VALUES(?,?,?,'PRODUCTION','REVOKED','EXTERNAL_RECORD','PENDING','CHANGE:SEC-123',now()-interval '1 minute',now(),?) RETURNING evidence_id
            """,Long.class,caseId,key,occurrence,user);
        jdbc.update("""
            INSERT INTO secret_lifecycle_evidence_reviews(evidence_id,decision,reason_code,expected_evidence_version,case_version,reviewed_by_user_id)
            VALUES(?,'APPROVE','EXTERNAL_RECORD_CONFIRMED',1,1,?)
            """,evidence,reviewer);
        assertThat(jdbc.queryForObject("SELECT verification_level FROM secret_current_lifecycle_evidence WHERE evidence_id=?",String.class,evidence)).isEqualTo("APPROVED_MANUAL");
        assertThat(repository.retiredHistory(rows())).isFalse();
        assertThat(inventory(filters("ALL","NORMAL_INVENTORY")).get("total")).isEqualTo(0L);
    }
    @Test void anActiveCaseUnknownPresenceOrReassessmentBlocksRetiredHistory() {
        provider(caseId,occurrence,"PRODUCTION","REVOKED");
        jdbc.update("UPDATE secret_case_occurrences SET response_status='IN_PROGRESS' WHERE case_id=?",caseId);
        assertThat(repository.retiredHistory(rows())).isFalse();
        jdbc.update("UPDATE secret_case_occurrences SET response_status='RESOLVED' WHERE case_id=?",caseId);
        jdbc.update("UPDATE secret_occurrences SET presence_status='UNKNOWN' WHERE occurrence_id=?",occurrence);
        assertThat(repository.retiredHistory(rows())).isFalse();
        jdbc.update("UPDATE secret_occurrences SET presence_status='MISSING',policy_recheck_required=true WHERE occurrence_id=?",occurrence);
        assertThat(repository.retiredHistory(rows())).isFalse();
        assertThat(inventory(filters("ALL","NORMAL_INVENTORY")).get("total")).isEqualTo(0L);
    }
    @Test void sourceFilteringCannotHideAnotherAuthorizedLocationsPendingWork() {
        provider(caseId,occurrence,"PRODUCTION","REVOKED");
        long other=connection("AWS"),otherScope=scope(other,"PRODUCTION");grant(user,other);
        occurrence(other,otherScope,"DEV","UNKNOWN","PRESENT");
        assertThat(repository.retiredHistory(rows())).isFalse();
        assertThat(inventory(filters("GITHUB","NORMAL_INVENTORY")).get("total")).isEqualTo(0L);
        var item=items(inventory(filters("GITHUB","ALL"))).getFirst();
        assertThat(item.get("inventorySubtype")).isNull();assertThat(item.get("workBucket")).isEqualTo("NEEDS_DECISION");
        assertThat(item.get("visibleLocationCount")).isEqualTo(2);assertThat(item.get("matchedLocationCount")).isEqualTo(1);
    }
    @Test void proofFromAHiddenSourceCannotChangeTheVisibleKeysClassification() {
        long other=connection("AWS"),otherScope=scope(other,"PRODUCTION");
        long hidden=occurrence(other,otherScope,"DEV","ABNORMAL","MISSING");
        jdbc.update("INSERT INTO secret_case_occurrences(case_id,occurrence_id,credential_set_id,response_status) VALUES(?,?,?,'RESOLVED')",caseId,hidden,key);
        var before=items(inventory(filters("ALL","ALL"))).getFirst();
        provider(caseId,hidden,"PRODUCTION","REVOKED");
        assertThat(repository.retiredHistory(rows())).isFalse();
        assertThat(items(inventory(filters("ALL","ALL"))).getFirst()).isEqualTo(before);
        assertThat(repository.retiredHistory(repository.visible(reviewer,key,filters("ALL","ALL")))).isTrue();
    }
    @Test void proofInAnotherOriginAndLaterSuccessfulAuthenticationCannotBeReused() {
        long otherScope=scope(connection,"TEST"),otherOccurrence=occurrence(connection,otherScope,"DEV","ABNORMAL","MISSING");
        long otherCase=caseFor(otherOccurrence,"TEST");provider(otherCase,otherOccurrence,"TEST","REVOKED");
        assertThat(repository.retiredHistory(rows())).isFalse();
        provider(caseId,occurrence,"PRODUCTION","REVOKED");assertThat(repository.retiredHistory(rows())).isTrue();
        validation(occurrence,"VALID","AUTHENTICATED");
        assertThat(repository.retiredHistory(rows())).isFalse();
    }
    private List<SecretLocationRepository.Row> rows(){return repository.visible(user,key,filters("ALL","ALL"));}
    private SecretInventoryFilters filters(String source,String work){return new SecretInventoryFilters("PRODUCTION",source,"ALL","ALL","ALL",work,"ALL","ALL","ALL");}
    private Map<String,Object> inventory(SecretInventoryFilters filters){return tx.execute(status->service.inventory("security",filters,0,20,null));}
    @SuppressWarnings("unchecked") private List<Map<String,Object>> items(Map<String,Object> page){return (List<Map<String,Object>>)page.get("items");}
    private long user(String login){return jdbc.queryForObject("INSERT INTO dashboard_users(login_id,password_hash,display_name,role) VALUES(?,'hash',?,'ADMIN') RETURNING user_id",Long.class,login,login);}
    private void grant(long person,long connection){jdbc.update("INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source) VALUES(?,'SECURITY',?,?,'MANUAL')",person,connection,person);}
    private long connection(String provider){return jdbc.queryForObject("INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version) VALUES(?,'safe','private-auth','ACTIVE',1) RETURNING connection_id",Long.class,provider);}
    private long scope(long connection,String origin){return jdbc.queryForObject("""
        INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,enabled,response_origin,
            response_origin_version,response_origin_set_by_user_id,response_origin_set_at)
        VALUES(?,gen_random_uuid()::text,1,'TEXT','private-path',true,?,1,?,now()) RETURNING scope_id
        """,Long.class,connection,origin,user);}
    private long occurrence(long connection,long scope,String environment,String exposure,String presence){return jdbc.queryForObject("""
        INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,environment,exposure_status,
            exposure_range,presence_status,policy_assessed_origin_version,first_seen_at,last_seen_at)
        VALUES(?,?,?,'private-path-'||gen_random_uuid()::text,'L1',?,?,'UNKNOWN',?,1,now()-interval '1 hour',now()-interval '1 hour') RETURNING occurrence_id
        """,Long.class,key,connection,scope,environment,exposure,presence);}
    private long caseFor(long occurrence,String origin){long result=jdbc.queryForObject("""
        INSERT INTO secret_response_cases(credential_set_id,opening_occurrence_id,opened_by_user_id,opening_reason,case_origin,action_status,version)
        VALUES(?,?,?,'APPROVED_EVIDENCE',?,'RESOLVED',1) RETURNING case_id
        """,Long.class,key,occurrence,user,origin);jdbc.update("INSERT INTO secret_case_occurrences(case_id,occurrence_id,credential_set_id,response_status) VALUES(?,?,?,'RESOLVED')",result,occurrence,key);return result;}
    private void provider(long caseId,long source,String origin,String kind){
        jdbc.update("INSERT INTO secret_lifecycle_provider_writers(database_role) VALUES(current_user) ON CONFLICT DO NOTHING");
        jdbc.update("INSERT INTO secret_lifecycle_provider_capabilities VALUES('TEST_RETIREMENT','1','PROVIDER_LIFECYCLE',?) ON CONFLICT DO NOTHING",kind);
        jdbc.update("""
            INSERT INTO secret_credential_lifecycle_evidence(case_id,credential_set_id,source_occurrence_id,origin,kind,verification_method,
                verification_level,provider_validator_id,validator_version,endpoint_class,reason_code,performed_at,observed_at)
            VALUES(?,?,?,?,?,'PROVIDER','PROVIDER_VERIFIED','TEST_RETIREMENT','1','PROVIDER_LIFECYCLE','CONFIRMED_KEY_RETIRED',now()-interval '1 minute',now())
            """,caseId,key,source,origin,kind);
    }
    private void validation(long source,String result,String reason){
        var location=jdbc.queryForMap("SELECT connection_id,scope_id FROM secret_occurrences WHERE occurrence_id=?",source);
        long job=jdbc.queryForObject("""
            INSERT INTO secret_jobs(kind,connection_id,requested_by_user_id,scheduled_at,available_at,attempt_no,max_attempts,status,finished_at)
            VALUES('FULL_SCAN',?,?,now(),now(),0,1,'SUCCEEDED',now()) RETURNING job_id
            """,Long.class,location.get("connection_id"),user);
        long run=jdbc.queryForObject("""
            INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,collection_status,detection_status,validation_status,result_status)
            VALUES(?,?,'MANUAL',1,now(),now(),'SUCCEEDED','SUCCEEDED','SUCCEEDED','SUCCEEDED') RETURNING run_id
            """,Long.class,job,location.get("connection_id"));
        long runScope=jdbc.queryForObject("INSERT INTO secret_run_scopes(run_id,scope_id,collection_status) VALUES(?,?,'SUCCEEDED') RETURNING run_scope_id",Long.class,run,location.get("scope_id"));
        long tool=jdbc.queryForObject("INSERT INTO secret_tool_runs(run_scope_id,engine,engine_version,config_hash,status) VALUES(?,'GITLEAKS','1','test','SUCCEEDED') RETURNING tool_run_id",Long.class,runScope);
        jdbc.update("INSERT INTO secret_findings(occurrence_id,run_id,tool_run_id,finding_key,rule_id,rule_version,detected_at) VALUES(?,?,?,'test','aws-key','1',now())",source,run,tool);
        jdbc.update("""
            INSERT INTO secret_validation_attempts(credential_set_id,run_id,job_id,validator_id,validator_version,endpoint_class,
                requested_at,completed_at,provider_checked_at,result,reason_code)
            VALUES(?,?,?,'AWS_STS_GET_CALLER_IDENTITY','1','AWS_STS',now(),now(),now(),?,?)
            """,key,run,job,result,reason);
    }
}
