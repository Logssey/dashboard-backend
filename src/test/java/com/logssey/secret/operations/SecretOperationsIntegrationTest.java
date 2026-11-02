package com.logssey.secret.operations;

import java.time.*;
import java.util.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import com.logssey.secret.access.SecretAccessService;
import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import static org.assertj.core.api.Assertions.*;

class SecretOperationsIntegrationTest {
    static final com.logssey.secret.testing.SecretTestPostgres PG=new com.logssey.secret.testing.SecretTestPostgres();
    static JdbcTemplate jdbc;static DataSourceTransactionManager manager;SecretOperationsStore store;
    final UUID instance=UUID.randomUUID();long connection,user;
    @BeforeAll static void start(){PG.start();var ds=new DriverManagerDataSource(PG.getJdbcUrl(),PG.getUsername(),PG.getPassword());Flyway.configure().dataSource(ds).load().migrate();jdbc=new JdbcTemplate(ds);manager=new DataSourceTransactionManager(ds);}
    @AfterAll static void stop(){PG.stop();}
    @BeforeEach void seed(){
        jdbc.execute("TRUNCATE secret_connections,dashboard_users,secret_worker_heartbeats,secret_operations_alerts RESTART IDENTITY CASCADE");
        store=new SecretOperationsStore(jdbc,manager,Duration.ofMinutes(2),Duration.ofMinutes(2),1);
        connection=jdbc.queryForObject("INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version) VALUES('GITHUB','Synthetic operations fixture','fixture','ACTIVE',1) RETURNING connection_id",Long.class);
        user=jdbc.queryForObject("INSERT INTO dashboard_users(login_id,password_hash,display_name,role) VALUES('ops','hash','Ops','ADMIN') RETURNING user_id",Long.class);
    }
    void beat(boolean enabled){store.heartbeat(new SecretOperationsStore.Beat(instance,"secret-worker","EXECUTOR",enabled,"IDLE",30000,null,null,OffsetDateTime.now(ZoneOffset.UTC),null,null));}
    long job(int delayMinutes){return jdbc.queryForObject("INSERT INTO secret_jobs(kind,connection_id,scheduled_at,available_at,attempt_no,max_attempts,status) VALUES('FULL_SCAN',?,now(),now()+(?*interval '1 minute'),0,3,'PENDING') RETURNING job_id",Long.class,connection,delayMinutes);}
    long openCount(){return jdbc.queryForObject("SELECT count(*) FROM secret_operations_alerts WHERE status='OPEN'",Long.class);}
    long occurrence(){
        long scope=jdbc.queryForObject("INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,history_limit,enabled) VALUES(?,?,1,'GITHUB_REPOSITORY_FILES','github://Sample/repo/main/fixtures/','CURRENT_COMMIT_ONLY',true) RETURNING scope_id",Long.class,connection,UUID.randomUUID().toString());
        long key=jdbc.queryForObject("INSERT INTO secret_credential_sets(issuer,credential_type,component_state,fingerprint,fingerprint_key_version,masked_label,first_seen_at,last_seen_at) VALUES('GITHUB','GITHUB_CLASSIC_PAT','CONFIRMED',?,'fixture-v1','GITHUB masked',now(),now()) RETURNING credential_set_id",Long.class,java.security.SecureRandom.getSeed(32));
        return jdbc.queryForObject("INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at) VALUES(?,?,?,'fixture-only','L1','UNKNOWN','UNKNOWN','UNKNOWN','PRESENT',now(),now()) RETURNING occurrence_id",Long.class,key,connection,scope);
    }
    void terminal(String kind,String purpose,long target,String state,String reason,int ageDays){
        jdbc.update("INSERT INTO secret_jobs(kind,purpose,connection_id,target_occurrence_id,scheduled_at,available_at,created_at,finished_at,attempt_no,max_attempts,status,last_error_code) VALUES(?,?,?,?,now()-(?*interval '1 day'),now()-(?*interval '1 day'),now()-(?*interval '1 day'),clock_timestamp()-(?*interval '1 day'),1,3,?,?)",kind,purpose,connection,target,ageDays,ageDays,ageDays,ageDays,state,reason);
    }
    @Test void oldTerminalFailureNeedsActualReplacementSuccessForTheSamePurposeAndTarget(){
        long target=occurrence(),other=occurrence();
        terminal("REVALIDATE","CREDENTIAL_VALIDITY",target,"FAILED","SOURCE_UNAVAILABLE",40);store.monitor();
        assertThat(store.alerts("OPEN",0,20).toString()).contains("CREDENTIAL_VALIDITY_JOB_FAILED");
        terminal("REVALIDATE","CREDENTIAL_VALIDITY",target,"CANCELLED","STALE_BASELINE",0);
        terminal("REVALIDATE","CREDENTIAL_VALIDITY",other,"SUCCEEDED",null,0);store.monitor();assertThat(openCount()).isEqualTo(1);
        terminal("REVALIDATE","CREDENTIAL_VALIDITY",target,"SUCCEEDED",null,0);store.monitor();assertThat(openCount()).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_scan_runs",Long.class)).isZero();
    }
    @Test void expectedCancellationStaleBaselineAndSuccessfulInvalidValidationAreNotOperationalFailures(){
        long target=occurrence();terminal("ASSESS","SEVERITY_ASSESSMENT",target,"FAILED","STALE_BASELINE",0);
        terminal("REVALIDATE","CREDENTIAL_VALIDITY",target,"CANCELLED","APPROVAL_CHANGED",0);
        terminal("REVALIDATE","CREDENTIAL_VALIDITY",target,"SUCCEEDED","KEY_REJECTED",0);
        store.monitor();assertThat(openCount()).isZero();
    }
    @Test void assessmentAndOptionalPermissionEnrichmentHaveIndependentPersistentTaskAlerts(){
        long target=occurrence();terminal("ASSESS","SEVERITY_ASSESSMENT",target,"FAILED","ASSESSMENT_PROCESSING_FAILED",30);store.monitor();
        assertThat(store.alerts("OPEN",0,20).toString()).contains("SEVERITY_ASSESSMENT_JOB_FAILED");
        terminal("ASSESS","SEVERITY_ASSESSMENT",target,"SUCCEEDED",null,0);store.monitor();assertThat(openCount()).isZero();
        if(jdbc.queryForObject("SELECT to_regclass('secret_permission_requests') IS NOT NULL",Boolean.class)){
            terminal("ENRICH","PERMISSION_ASSISTANCE",target,"FAILED","PERMISSION_OBSERVER_FAILED",30);store.monitor();
            assertThat(store.alerts("OPEN",0,20).toString()).contains("PERMISSION_ASSISTANCE_JOB_FAILED");
            terminal("ENRICH","PERMISSION_ASSISTANCE",target,"SUCCEEDED",null,0);store.monitor();assertThat(openCount()).isZero();
        }
    }
    @Test void readyQueueAlertsDeduplicateAndRecoverWithoutAnyExternalMessages(){
        beat(true);long id=job(-5);store.monitor();store.monitor();
        assertThat(openCount()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT occurrences FROM secret_operations_alerts",Long.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_operations_alert_events",Long.class)).isEqualTo(1);
        jdbc.update("UPDATE secret_jobs SET status='SUCCEEDED',finished_at=now() WHERE job_id=?",id);store.monitor();
        assertThat(openCount()).isZero();assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_operations_alert_events",Long.class)).isEqualTo(2);
        job(-5);store.monitor();assertThat(openCount()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT occurrences FROM secret_operations_alerts",Long.class)).isEqualTo(2);
    }
    @Test void futureBackoffDisabledExecutorAndNormalEmptyQueueDoNotAlarm(){
        beat(true);job(10);store.monitor();assertThat(openCount()).isZero();
        jdbc.execute("TRUNCATE secret_jobs RESTART IDENTITY CASCADE");beat(false);job(-5);store.monitor();assertThat(openCount()).isZero();
        assertThat(store.health().toString()).contains("DISABLED","delayed");
    }
    @Test void processCanBeAliveWhilePollProgressFailsAndThenRecovers(){
        beat(true);jdbc.update("UPDATE secret_worker_heartbeats SET started_at=now()-interval '1 hour',last_success_at=now()-interval '1 hour'");
        store.monitor();assertThat(openCount()).isEqualTo(1);assertThat(store.alerts("OPEN",0,20).toString()).contains("POLL_FAILED");
        beat(true);store.monitor();assertThat(openCount()).isZero();
    }
    @Test void independentApiMonitorRaisesDeadWorkerAlertWhileReadsStayReadOnly(){
        beat(true);jdbc.update("UPDATE secret_worker_heartbeats SET last_heartbeat_at=now()-interval '5 minutes'");
        var service=new SecretOperationsService(jdbc,manager,new SecretAccessService(jdbc),Duration.ofMinutes(2),Duration.ofMinutes(2),1);
        jdbc.update("INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source) VALUES(?,'OPERATIONS',NULL,?,'MANUAL')",user,user);
        assertThat(service.health("ops").toString()).contains("STALE");assertThat(openCount()).isZero();
        var monitor=new SecretOperationsApiMonitor(service);monitor.poll();assertThat(openCount()).isEqualTo(1);
        beat(true);monitor.poll();assertThat(openCount()).isZero();
    }
    @Test void anotherDeploymentCannotMaskOrClearThisDeploymentWorkerAlert(){
        beat(true);jdbc.update("UPDATE secret_worker_heartbeats SET last_heartbeat_at=now()-interval '5 minutes'");
        var other=new SecretOperationsStore(jdbc,manager,Duration.ofMinutes(2),Duration.ofMinutes(2),1,"other-deployment");
        other.heartbeat(new SecretOperationsStore.Beat(UUID.randomUUID(),"other-deployment","EXECUTOR",false,"IDLE",30000,null,null,null,null,null));
        store.monitor();other.monitor();assertThat(openCount()).isEqualTo(1);
        assertThat(other.alerts("OPEN",0,20)).containsEntry("total",0L);
        assertThat(store.health().toString()).contains("STALE");
    }
    @Test void partialScanWithZeroFindingsRemainsPartialUntilNewSuccessfulScan(){
        beat(true);long id=job(0);jdbc.update("UPDATE secret_jobs SET status='SUCCEEDED',finished_at=now() WHERE job_id=?",id);
        jdbc.update("INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,finished_at,collection_status,detection_status,validation_status,result_status) VALUES(?,?,'MANUAL',1,now(),now(),now(),'PARTIAL','SKIPPED','SKIPPED','PARTIAL')",id,connection);
        store.monitor();assertThat(store.alerts("OPEN",0,20).toString()).contains("RUN_PARTIAL");
        long next=job(0);jdbc.update("UPDATE secret_jobs SET status='SUCCEEDED',finished_at=now() WHERE job_id=?",next);
        jdbc.update("INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,finished_at,collection_status,detection_status,validation_status,result_status) VALUES(?,?,'MANUAL',1,now(),now(),clock_timestamp(),'SUCCEEDED','SUCCEEDED','SKIPPED','SUCCEEDED')",next,connection);
        store.monitor();assertThat(openCount()).isZero();
    }
    @Test void scopedRoleCannotReadGlobalQueueAndLiveGrantRevocationApplies(){
        var service=new SecretOperationsService(jdbc,manager,new SecretAccessService(jdbc),Duration.ofMinutes(2),Duration.ofMinutes(2),1);
        jdbc.update("INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source) VALUES(?,'OPERATIONS',?,?,'MANUAL')",user,connection,user);
        assertThatThrownBy(()->service.health("ops")).isInstanceOfSatisfying(ApiException.class,e->assertThat(e.errorCode()).isEqualTo(ErrorCode.FORBIDDEN));
        jdbc.update("INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source) VALUES(?,'OPERATIONS',NULL,?,'MANUAL')",user,user);
        assertThat(service.health("ops")).containsEntry("status","AVAILABLE");
        jdbc.update("UPDATE secret_role_grants SET revoked_at=now() WHERE user_id=?",user);
        assertThatThrownBy(()->service.alerts("ops","OPEN",0,20)).isInstanceOf(ApiException.class);
    }
    @Test void auditAndAlertHistoryCannotBeRewrittenButNewFactsCanBeAppended(){
        beat(true);job(-5);store.monitor();
        assertThatThrownBy(()->jdbc.update("DELETE FROM secret_operations_alert_events")).isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
        jdbc.update("INSERT INTO secret_audit_events(event_type,actor_user_id,target_type,target_id,target_version,safe_changes) VALUES('MANUAL_SCAN_REGISTERED',?,'CONNECTION',?,1,'{}')",user,connection);
        assertThatThrownBy(()->jdbc.update("UPDATE secret_audit_events SET safe_changes='{}'::jsonb")).isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
    }
    @Test void temporarySnapshotCleanupIsBoundedAndLeavesActiveSnapshotsAndCoreLedgers(){
        UUID expired=UUID.randomUUID(),active=UUID.randomUUID();
        for(UUID id:List.of(expired,active))jdbc.update("INSERT INTO secret_query_snapshots(snapshot_id,scope,owner_user_id,as_of,created_at,expires_at,authorization_revision,scope_version_digest,normalized_filters,filter_digest,coverage_status,restricted_coverage) VALUES(?,'INVENTORY',?,now()-interval '1 hour',now()-interval '1 hour',?,'auth','scope','{}','filter','COMPLETE',false)",id,user,id.equals(expired)?OffsetDateTime.now().minusMinutes(1):OffsetDateTime.now().plusMinutes(5));
        job(0);assertThat(store.cleanupExpiredSnapshots(1)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_query_snapshots",Long.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT snapshot_id FROM secret_query_snapshots",UUID.class)).isEqualTo(active);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_jobs",Long.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_snapshot_retirements",Long.class)).isEqualTo(1);
    }
}
