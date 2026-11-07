package com.logssey.secretworker.usage;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.logssey.secret.aws.SecretAwsSourceCredentials;
import com.logssey.secret.usage.core.SecretUsageContext;
import com.logssey.secretworker.SecretJobProperties;
import com.logssey.secretworker.aws.AwsMetadataIdentity;
import com.logssey.secretworker.detection.SecretFindingNormalizer;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;

class UsageObservationExecutorTest {
    static final com.logssey.secret.testing.SecretTestPostgres DB=new com.logssey.secret.testing.SecretTestPostgres();static JdbcTemplate jdbc;static DataSourceTransactionManager tm;
    static final String KEY="AKIA"+"A".repeat(16),ACCOUNT="123456789012",REGION="ap-northeast-2";
    final AwsMetadataIdentity metadata=new AwsMetadataIdentity(new byte[32],"fixture");
    AwsUsageGateway gateway;UsageObservationExecutor executor;SecretUsageContext context;long occurrence,target;Instant eventTime;
    @BeforeAll static void db(){DB.start();var ds=new DriverManagerDataSource(DB.getJdbcUrl(),DB.getUsername(),DB.getPassword());jdbc=new JdbcTemplate(ds);tm=new DataSourceTransactionManager(ds);Flyway.configure().dataSource(ds).load().migrate();}
    @AfterAll static void stop(){DB.stop();}
    @BeforeEach void fixture(){
        jdbc.execute("TRUNCATE dashboard_users,secret_connections RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO dashboard_users(login_id,password_hash,display_name,role) VALUES('usage-security','hash','Security','ADMIN')");
        jdbc.update("INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version) VALUES('AWS','Usage reader','aws-profile:fixture','ACTIVE',1)");
        jdbc.update("INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,enabled,response_origin,response_origin_set_by_user_id,response_origin_set_at) VALUES(1,'iam',1,'IAM_ACCESS_KEY_METADATA','aws://123456789012/global/iam/access-keys',true,'PRODUCTION',1,clock_timestamp())");
        jdbc.update("INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source) VALUES(1,'SECURITY',1,1,'MANUAL')");
        jdbc.update("INSERT INTO secret_credential_sets(issuer,credential_type,component_state,issuer_connection_id,external_key_ref,masked_label,first_seen_at,last_seen_at) VALUES('AWS','AWS_IAM_ACCESS_KEY','METADATA_ONLY',1,?,'AWS key masked',clock_timestamp(),clock_timestamp())",metadata.reference(ACCOUNT,KEY));
        occurrence=jdbc.queryForObject("INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at) VALUES(1,1,1,'protected-location','iam/access-key','UNKNOWN','UNKNOWN','UNKNOWN','PRESENT',clock_timestamp(),clock_timestamp()) RETURNING occurrence_id",Long.class);
        target=jdbc.queryForObject("""
INSERT INTO secret_usage_targets(occurrence_id,collector_connection_id,collector_scope_id,account_ref,region,credential_revision,scope_revision,source_scope_version,collector_scope_version,collector_scope_revision,collector_auth_ref,collector_approved_ref,approved_by_user_id,enabled,schedule_enabled)
VALUES(?,1,1,'123456789012','ap-northeast-2',1,1,1,1,1,'aws-profile:fixture','aws://123456789012/global/iam/access-keys',1,true,true) RETURNING target_id
""",Long.class,occurrence);
        context=new SecretUsageContext(jdbc);eventTime=context.now().minusHours(1).toInstant();gateway=mock(AwsUsageGateway.class);when(gateway.accountId()).thenReturn(ACCOUNT);when(gateway.userNames()).thenReturn(List.of("fixture"));when(gateway.accessKeyIds("fixture")).thenReturn(List.of(KEY));
        SecretAwsSourceCredentials source=mock(SecretAwsSourceCredentials.class);when(source.authRef()).thenReturn("aws-profile:fixture");
        @SuppressWarnings("unchecked")ObjectProvider<SecretAwsSourceCredentials> sources=mock(ObjectProvider.class);when(sources.getIfAvailable()).thenReturn(source);
        @SuppressWarnings("unchecked")ObjectProvider<SecretFindingNormalizer> normalizers=mock(ObjectProvider.class);
        @SuppressWarnings("unchecked")ObjectProvider<AwsMetadataIdentity> metadataProvider=mock(ObjectProvider.class);when(metadataProvider.getIfAvailable()).thenReturn(metadata);
        var properties=new SecretJobProperties(true,Duration.ofSeconds(30),Duration.ofSeconds(30),10,Duration.ofSeconds(1),Duration.ofSeconds(30));
        executor=new UsageObservationExecutor(jdbc,tm,properties,sources,normalizers,metadataProvider,c->gateway,new AwsUsageObserver(d->{},100,5000),d->{try{Thread.sleep(d);}catch(InterruptedException e){throw new IllegalStateException();}});
    }
    AwsUsageGateway.Page page(String next){return new AwsUsageGateway.Page(List.of(new AwsUsageGateway.Event("11111111-1111-4111-8111-111111111111",KEY,"GetCallerIdentity","sts.amazonaws.com",eventTime,"{\"eventVersion\":\"1.09\",\"eventName\":\"GetCallerIdentity\",\"sourceIPAddress\":\"PRIVATE_SOURCE\"}")),next);}
    long request(){var tx=new org.springframework.transaction.support.TransactionTemplate(tm);return tx.execute(s->{var now=context.now();return context.enqueue(context.occurrence(occurrence),context.target(target),1,now.minusDays(7),now,"MANUAL");});}
    @Test void exactEventsPersistOnceAcrossRepeatedRequestsAndNeverProduceAScanOrGrade(){
        when(gateway.lookup(anyString(),eq(KEY),any(),any(),isNull())).thenReturn(page(null));
        long first=request();assertThat(executor.execute(executor.claim().orElseThrow())).isTrue();
        long second=request();assertThat(executor.execute(executor.claim().orElseThrow())).isTrue();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_usage_observations",Long.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT observation_status FROM secret_usage_requests WHERE request_id=?",String.class,second)).isEqualTo("OBSERVED");
        assertThat(jdbc.queryForObject("SELECT event_count FROM secret_usage_requests WHERE request_id=?",Integer.class,second)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT row_to_json(o)::text FROM secret_usage_observations o LIMIT 1",String.class)).doesNotContain(KEY,"PRIVATE_SOURCE","sourceIPAddress");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_scan_runs",Long.class)).isZero();assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_severity_assessments",Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT request_id FROM secret_usage_observations LIMIT 1",Long.class)).isEqualTo(first);
    }
    @Test void completeEmptyQueryIsNotObservedWithinItsExactScope(){when(gateway.lookup(anyString(),anyString(),any(),any(),isNull())).thenReturn(new AwsUsageGateway.Page(List.of(),null));long id=request();assertThat(executor.execute(executor.claim().orElseThrow())).isTrue();var row=context.request(id);assertThat(row.get("status")).isEqualTo("COMPLETE");assertThat(row.get("observation_status")).isEqualTo("NOT_OBSERVED_IN_SCOPE");assertThat(row.get("binding_level")).isEqualTo("EXACT_CREDENTIAL");}
    @Test void permissionRevocationDuringReadPreventsAllObservationWrites(){when(gateway.lookup(anyString(),anyString(),any(),any(),isNull())).thenAnswer(i->{jdbc.update("UPDATE secret_role_grants SET revoked_at=clock_timestamp() WHERE user_id=1");return page(null);});long id=request();assertThat(executor.execute(executor.claim().orElseThrow())).isFalse();assertThat(context.request(id).get("status")).isEqualTo("CANCELLED");assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_usage_observations",Long.class)).isZero();}
    @Test void cooldownThenDeniedFirstPagePreservesEarlierObservedPartialResult(){
        when(gateway.lookup(anyString(),anyString(),any(),any(),isNull())).thenReturn(page("next"));when(gateway.lookup(anyString(),anyString(),any(),any(),eq("next"))).thenThrow(new AwsUsageFailure("USAGE_RATE_LIMITED",true,Instant.now().plusSeconds(60)));
        long id=request();var first=executor.claim().orElseThrow();assertThat(executor.execute(first)).isFalse();assertThat(context.request(id).get("status")).isEqualTo("PENDING");
        jdbc.update("UPDATE secret_jobs SET available_at=clock_timestamp() WHERE job_id=?",first.jobId());
        when(gateway.lookup(anyString(),anyString(),any(),any(),isNull())).thenThrow(new AwsUsageFailure("USAGE_ACCESS_DENIED",false,null));assertThat(executor.execute(executor.claim().orElseThrow())).isFalse();var row=context.request(id);
        assertThat(row.get("status")).isEqualTo("PARTIAL");assertThat(row.get("observation_status")).isEqualTo("OBSERVED");assertThat(row.get("coverage_status")).isEqualTo("PARTIAL");assertThat(row.get("event_count")).isEqualTo(1);assertThat(row.get("binding_level")).isEqualTo("EXACT_CREDENTIAL");
    }
    @Test void oldLeaseCannotPublishAndNewGenerationCanComplete(){when(gateway.lookup(anyString(),anyString(),any(),any(),isNull())).thenReturn(page(null));request();var old=executor.claim().orElseThrow();jdbc.update("UPDATE secret_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE job_id=?",old.jobId());var current=executor.claim().orElseThrow();assertThat(current.generation()).isGreaterThan(old.generation());assertThat(executor.execute(old)).isFalse();assertThat(executor.execute(current)).isTrue();assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_usage_observations",Long.class)).isEqualTo(1);}
    @Test void twoSchedulersReserveOnceAndSixHoursRemainUntilNextRun()throws Exception{
        var pool=Executors.newFixedThreadPool(2);try{var tasks=List.<Callable<Integer>>of(()->new UsageObservationScheduler(jdbc,tm).reserveDue(),()->new UsageObservationScheduler(jdbc,tm).reserveDue());var futures=pool.invokeAll(tasks);int count=0;for(var f:futures)count+=f.get(15,TimeUnit.SECONDS);assertThat(count).isEqualTo(1);assertThat(new UsageObservationScheduler(jdbc,tm).reserveDue()).isZero();
            assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_usage_requests",Long.class)).isEqualTo(1);assertThat(jdbc.queryForObject("SELECT next_scheduled_at>clock_timestamp()+interval '5 hours' FROM secret_usage_targets WHERE target_id=?",Boolean.class,target)).isTrue();
        }finally{pool.shutdownNow();}
    }
    @Test void accountMismatchNeverQueriesTheKey(){when(gateway.accountId()).thenReturn("999999999999");long id=request();assertThat(executor.execute(executor.claim().orElseThrow())).isFalse();assertThat(context.request(id).get("observation_status")).isEqualTo("UNAVAILABLE");verify(gateway,never()).userNames();verify(gateway,never()).lookup(anyString(),anyString(),any(),any(),any());}
    @Test void schedulerSkipsAnOccurrenceLockedByAManualRequest()throws Exception{
        var locked=new CountDownLatch(1);var release=new CountDownLatch(1);var pool=Executors.newSingleThreadExecutor();
        try{var manual=pool.submit(()->new org.springframework.transaction.support.TransactionTemplate(tm).execute(s->{jdbc.queryForObject("SELECT occurrence_id FROM secret_occurrences WHERE occurrence_id=? FOR UPDATE",Long.class,occurrence);locked.countDown();try{if(!release.await(10,TimeUnit.SECONDS))throw new IllegalStateException("TEST_TIMEOUT");}catch(InterruptedException e){throw new IllegalStateException(e);}var now=context.now();return context.enqueue(context.occurrence(occurrence),context.target(target),1,now.minusDays(7),now,"MANUAL");}));
            assertThat(locked.await(10,TimeUnit.SECONDS)).isTrue();assertThat(new UsageObservationScheduler(jdbc,tm).reserveDue()).isZero();release.countDown();assertThat(manual.get(10,TimeUnit.SECONDS)).isPositive();assertThat(new UsageObservationScheduler(jdbc,tm).reserveDue()).isZero();assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_usage_requests",Long.class)).isEqualTo(1);
        }finally{release.countDown();pool.shutdownNow();}
    }
    @Test void aRescheduledRequestSharesOneTotalPageAndEventBudget(){
        long id=request();jdbc.update("UPDATE secret_usage_requests SET page_count=99,event_count=4999,binding_level='EXACT_CREDENTIAL' WHERE request_id=?",id);
        var second=new AwsUsageGateway.Event("22222222-2222-4222-8222-222222222222",KEY,"GetCallerIdentity","sts.amazonaws.com",eventTime,"{\"eventVersion\":\"1.09\",\"eventName\":\"GetCallerIdentity\"}");
        when(gateway.lookup(anyString(),anyString(),any(),any(),isNull())).thenReturn(new AwsUsageGateway.Page(List.of(page(null).events().getFirst(),second),"next"));
        assertThat(executor.execute(executor.claim().orElseThrow())).isFalse();var row=context.request(id);assertThat(row.get("page_count")).isEqualTo(100);assertThat(row.get("event_count")).isEqualTo(5000);assertThat(row.get("coverage_status")).isEqualTo("PARTIAL");assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_usage_observations",Long.class)).isEqualTo(1);verify(gateway,never()).lookup(anyString(),anyString(),any(),any(),eq("next"));
    }
    @Test void exhaustedRequestBudgetDoesNotCallAnyProvider(){long id=request();jdbc.update("UPDATE secret_usage_requests SET page_count=100 WHERE request_id=?",id);assertThat(executor.execute(executor.claim().orElseThrow())).isFalse();assertThat(context.request(id).get("coverage_status")).isEqualTo("PARTIAL");verifyNoInteractions(gateway);}
    @Test void finalLeaseExpiryPreservesPreviouslyObservedPartialUsage(){
        when(gateway.lookup(anyString(),anyString(),any(),any(),isNull())).thenReturn(page("next"));when(gateway.lookup(anyString(),anyString(),any(),any(),eq("next"))).thenThrow(new AwsUsageFailure("USAGE_RATE_LIMITED",true,Instant.now().plusSeconds(60)));
        long id=request();var first=executor.claim().orElseThrow();assertThat(executor.execute(first)).isFalse();jdbc.update("UPDATE secret_jobs SET available_at=clock_timestamp() WHERE job_id=?",first.jobId());var last=executor.claim().orElseThrow();
        jdbc.update("UPDATE secret_jobs SET attempt_no=max_attempts,lease_until=clock_timestamp()-interval '1 second' WHERE job_id=?",last.jobId());assertThat(executor.claim()).isEmpty();
        var row=context.request(id);assertThat(row.get("status")).isEqualTo("PARTIAL");assertThat(row.get("observation_status")).isEqualTo("OBSERVED");assertThat(row.get("coverage_status")).isEqualTo("PARTIAL");assertThat(row.get("event_count")).isEqualTo(1);assertThat(row.get("binding_level")).isEqualTo("EXACT_CREDENTIAL");
    }
    @Test void staleTargetsAtTheBatchFrontDoNotStarveALaterApprovedTarget(){
        jdbc.update("UPDATE secret_usage_targets SET next_scheduled_at=clock_timestamp()-interval '1 minute' WHERE target_id=?",target);
        jdbc.update("""
INSERT INTO secret_usage_targets(occurrence_id,collector_connection_id,collector_scope_id,account_ref,region,credential_revision,scope_revision,source_scope_version,collector_scope_version,collector_scope_revision,collector_auth_ref,collector_approved_ref,approved_by_user_id,enabled,schedule_enabled,next_scheduled_at)
SELECT ?,1,1,lpad(n::text,12,'0'),'ap-northeast-2',1,1,999,1,1,'aws-profile:fixture','aws://123456789012/global/iam/access-keys',1,true,true,clock_timestamp()-interval '2 minutes' FROM generate_series(1,100) n
""",occurrence);
        var scheduler=new UsageObservationScheduler(jdbc,tm);
        assertThat(scheduler.reserveDue()).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_usage_requests",Long.class)).isZero();
        assertThat(scheduler.reserveDue()).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT target_id FROM secret_usage_requests",Long.class)).isEqualTo(target);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_usage_targets WHERE enabled AND schedule_enabled",Long.class)).isEqualTo(101);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_usage_targets WHERE source_scope_version=999",Long.class)).isEqualTo(100);
    }
    @Test void reservedLookupBudgetSurvivesWorkerDeathBeforePageCommit(){
        long id=request();var crashed=executor.claim().orElseThrow();
        jdbc.update("UPDATE secret_usage_requests SET lookup_budget_used=99 WHERE request_id=?",id);
        jdbc.update("UPDATE secret_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE job_id=?",crashed.jobId());
        var recovered=executor.claim().orElseThrow();
        when(gateway.lookup(anyString(),anyString(),any(),any(),isNull())).thenReturn(page("more"));
        assertThat(executor.execute(recovered)).isFalse();
        var row=context.request(id);assertThat(row.get("lookup_budget_used")).isEqualTo(100);assertThat(row.get("page_count")).isEqualTo(1);assertThat(row.get("coverage_status")).isEqualTo("PARTIAL");assertThat(row.get("observation_status")).isEqualTo("OBSERVED");
        verify(gateway,times(1)).lookup(anyString(),anyString(),any(),any(),isNull());verify(gateway,never()).lookup(anyString(),anyString(),any(),any(),eq("more"));
    }
}
