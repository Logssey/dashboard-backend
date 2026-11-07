package com.logssey.secretworker.usage;

import static com.logssey.secret.permission.core.SecretPermissionContext.*;
import com.logssey.secret.usage.core.SecretUsageContext;
import com.logssey.secret.aws.SecretAwsSourceCredentials;
import com.logssey.secretworker.SecretJobProperties;
import com.logssey.secretworker.aws.AwsMetadataIdentity;
import com.logssey.secretworker.detection.SecretFindingNormalizer;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Independent ENRICH lease. No ScanRun, validation result or severity-v2 writes. */
@Service
public class UsageObservationExecutor {
    public record Lease(long jobId,long requestId,long occurrenceId,UUID token,long generation) { }
    @FunctionalInterface public interface GatewayFactory { AwsUsageGateway create(SecretAwsSourceCredentials credentials); }
    private final JdbcTemplate jdbc;private final TransactionTemplate tx;private final SecretUsageContext contexts;private final SecretJobProperties properties;
    private final ObjectProvider<SecretAwsSourceCredentials> credentials;private final ObjectProvider<SecretFindingNormalizer> normalizers;private final ObjectProvider<AwsMetadataIdentity> metadata;
    private final GatewayFactory gateways;private final AwsUsageObserver observer;private final AwsUsageObserver.Sleeper sleeper;
    @org.springframework.beans.factory.annotation.Autowired
    public UsageObservationExecutor(JdbcTemplate jdbc,PlatformTransactionManager manager,SecretJobProperties properties,ObjectProvider<SecretAwsSourceCredentials> credentials,ObjectProvider<SecretFindingNormalizer> normalizers,ObjectProvider<AwsMetadataIdentity> metadata){
        this(jdbc,manager,properties,credentials,normalizers,metadata,AwsSdkUsageGateway::new,new AwsUsageObserver(),UsageObservationExecutor::sleep);
    }
    public UsageObservationExecutor(JdbcTemplate jdbc,PlatformTransactionManager manager,SecretJobProperties properties,ObjectProvider<SecretAwsSourceCredentials> credentials,ObjectProvider<SecretFindingNormalizer> normalizers,ObjectProvider<AwsMetadataIdentity> metadata,GatewayFactory gateways,AwsUsageObserver observer,AwsUsageObserver.Sleeper sleeper){
        this.jdbc=jdbc;this.tx=new TransactionTemplate(manager);this.contexts=new SecretUsageContext(jdbc);this.properties=properties;this.credentials=credentials;this.normalizers=normalizers;this.metadata=metadata;this.gateways=gateways;this.observer=observer;this.sleeper=sleeper;
    }
    public Optional<Lease> claim(){return tx.execute(status->{
        var expired=jdbc.queryForList("SELECT job_id FROM secret_jobs WHERE kind='ENRICH' AND purpose='USAGE_OBSERVATION' AND status='LEASED' AND lease_until<=clock_timestamp() FOR UPDATE SKIP LOCKED");
        for(var e:expired){long id=number(e,"job_id");jdbc.update("UPDATE secret_jobs SET status=CASE WHEN attempt_no>=max_attempts THEN 'FAILED' ELSE 'PENDING' END,finished_at=CASE WHEN attempt_no>=max_attempts THEN clock_timestamp() ELSE NULL END,available_at=clock_timestamp(),lease_owner=NULL,lease_token=NULL,lease_until=NULL,last_error_code='USAGE_LEASE_EXPIRED' WHERE job_id=?",id);
            jdbc.update("UPDATE secret_usage_requests SET status=CASE WHEN (SELECT status FROM secret_jobs WHERE job_id=?)='FAILED' THEN CASE WHEN observation_status='OBSERVED' THEN 'PARTIAL' ELSE 'UNAVAILABLE' END ELSE 'PENDING' END,observation_status=CASE WHEN observation_status='OBSERVED' THEN 'OBSERVED' WHEN (SELECT status FROM secret_jobs WHERE job_id=?)='FAILED' THEN 'UNAVAILABLE' ELSE observation_status END,coverage_status=CASE WHEN observation_status='OBSERVED' THEN 'PARTIAL' ELSE coverage_status END,reason_codes=ARRAY['USAGE_LEASE_EXPIRED']::text[],completed_at=CASE WHEN (SELECT status FROM secret_jobs WHERE job_id=?)='FAILED' THEN clock_timestamp() ELSE NULL END WHERE job_id=?",id,id,id,id);}
        var rows=jdbc.queryForList("SELECT j.job_id,j.target_occurrence_id,j.lease_generation,r.request_id FROM secret_jobs j JOIN secret_usage_requests r USING(job_id) WHERE j.kind='ENRICH' AND j.purpose='USAGE_OBSERVATION' AND j.status='PENDING' AND j.available_at<=clock_timestamp() AND j.attempt_no<j.max_attempts ORDER BY j.available_at,j.job_id LIMIT 1 FOR UPDATE OF j SKIP LOCKED");
        if(rows.isEmpty())return Optional.empty();var row=rows.getFirst();var token=UUID.randomUUID();long generation=number(row,"lease_generation")+1;
        jdbc.update("UPDATE secret_jobs SET status='LEASED',lease_owner=?,lease_token=?,lease_generation=?,lease_until=clock_timestamp()+(?*interval '1 millisecond'),attempt_no=attempt_no+1,last_error_code=NULL WHERE job_id=?",token.toString(),token,generation,properties.leaseDuration().toMillis(),number(row,"job_id"));
        jdbc.update("UPDATE secret_usage_requests SET status='RUNNING',started_at=COALESCE(started_at,clock_timestamp()),completed_at=NULL WHERE request_id=?",number(row,"request_id"));
        return Optional.of(new Lease(number(row,"job_id"),number(row,"request_id"),number(row,"target_occurrence_id"),token,generation));
    });}
    public boolean execute(Lease lease){
        var lost=new AtomicBoolean();var thread=Executors.newSingleThreadScheduledExecutor(Thread.ofVirtual().name("usage-lease-heartbeat").factory());long interval=Math.max(1000,properties.leaseDuration().toMillis()/3);
        var timer=thread.scheduleWithFixedDelay(()->{try{if(!renew(lease))lost.set(true);}catch(RuntimeException failure){lost.set(true);}},interval,interval,TimeUnit.MILLISECONDS);
        try{
            var request=contexts.request(lease.requestId());Runnable guard=()->{if(lost.get()||!owned(lease)||!contexts.current(request))throw new ContextChanged();};guard.run();
            int remainingPages=100-((Number)request.get("page_count")).intValue();
            int remainingEvents=5000-((Number)request.get("event_count")).intValue();
            if(remainingPages<=0||remainingEvents<=0)return commit(lease,request,new AwsUsageObserver.Result("UNAVAILABLE","PARTIAL",List.of(remainingPages<=0?"USAGE_PAGE_LIMIT":"USAGE_EVENT_LIMIT"),0,0,List.of(),null),"EXACT_CREDENTIAL".equals(request.get("binding_level")));
            var c=contexts.occurrence(lease.occurrenceId());var target=contexts.target(number(request,"target_id"));var source=credentials.getIfAvailable();
            if(source==null||!source.authRef().equals(target.get("current_collector_auth_ref")))return finishUnavailable(lease,request,"COLLECTOR_NOT_CONFIGURED");
            try(var gateway=gateways.create(source)){
                guard.run();String account=gateway.accountId();if(!Objects.equals(account,target.get("account_ref")))return finishUnavailable(lease,request,"COLLECTOR_ACCOUNT_MISMATCH");
                String key=new AwsUsageKeyResolver(normalizers.getIfAvailable(),metadata.getIfAvailable()).resolve(c,account,gateway,guard);
                String region=target.get("region").toString();
                var result=observer.withBudget(remainingPages,remainingEvents).observe(gateway,region,key,time(request.get("window_start")).toInstant(),time(request.get("window_end")).toInstant(),guard,()->reserve(account,region,guard));
                return commit(lease,request,result,true);
            }
        }catch(ContextChanged invalid){cancel(lease,"USAGE_BASELINE_CHANGED");return false;}
        catch(AwsUsageFailure failure){var request=contexts.request(lease.requestId());return finishUnavailable(lease,request,failure.code());}
        catch(RuntimeException failure){var request=contexts.request(lease.requestId());return finishUnavailable(lease,request,"USAGE_OBSERVER_FAILED");}
        finally{timer.cancel(true);thread.shutdownNow();}
    }
    private void reserve(String account,String region,Runnable guard){
        OffsetDateTime slot=tx.execute(status->jdbc.queryForObject("""
INSERT INTO secret_usage_rate_limits(account_ref,region,next_available_at)
VALUES(?,?,clock_timestamp()+interval '1 second') ON CONFLICT(account_ref,region)
DO UPDATE SET next_available_at=greatest(secret_usage_rate_limits.next_available_at,clock_timestamp())+interval '1 second'
RETURNING next_available_at-interval '1 second'
""",OffsetDateTime.class,account,region));
        while(true){guard.run();var wait=Duration.between(contexts.now(),slot);if(wait.isNegative()||wait.isZero())return;sleeper.sleep(wait.compareTo(Duration.ofSeconds(1))>0?Duration.ofSeconds(1):wait);}
    }
    private boolean finishUnavailable(Lease lease,Map<String,Object> request,String reason){return commit(lease,request,new AwsUsageObserver.Result("UNAVAILABLE","UNKNOWN",List.of(reason),0,0,List.of(),null),false);}
    private boolean commit(Lease lease,Map<String,Object> request,AwsUsageObserver.Result result,boolean exact){return Boolean.TRUE.equals(tx.execute(status->{
        jdbc.queryForObject("SELECT job_id FROM secret_jobs WHERE job_id=? FOR UPDATE",Long.class,lease.jobId());if(!owned(lease))return false;
        lockBaseline(request);if(!contexts.current(request)){cancel(lease,"USAGE_BASELINE_CHANGED");return false;}
        var target=contexts.target(number(request,"target_id"));
        for(var event:result.observations())jdbc.update("""
INSERT INTO secret_usage_observations(source_kind,request_id,occurrence_id,credential_set_id,credential_revision,scope_revision,
 collector_connection_id,account_ref,region,provider_event_id,source_context_version,binding_level,coverage_status,action_code,
 action_result,actor_attribution,service_code,operation_code,event_at,window_start,window_end)
VALUES('PROVIDER',?,?,?,?,?,?,?,?,?,?,'EXACT_CREDENTIAL',?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING
""",lease.requestId(),request.get("occurrence_id"),request.get("credential_set_id"),request.get("credential_revision"),request.get("scope_revision"),target.get("collector_connection_id"),target.get("account_ref"),target.get("region"),UUID.fromString(event.eventRef()),request.get("source_context_version"),result.coverageStatus(),event.actionCode(),event.actionResult(),event.actorAttribution(),event.serviceCode(),event.operationCode(),event.eventTime().atOffset(ZoneOffset.UTC),request.get("window_start"),request.get("window_end"));
        long retained=jdbc.queryForObject("SELECT count(*) FROM secret_usage_observations WHERE request_id=? AND source_kind='PROVIDER'",Long.class,lease.requestId());
        boolean hasObserved=retained>0||!result.observations().isEmpty()||"OBSERVED".equals(request.get("observation_status"));
        String coverage=hasObserved&&!"COMPLETE".equals(result.coverageStatus())?"PARTIAL":result.coverageStatus();
        String observed=hasObserved?"OBSERVED":result.observationStatus();
        int events=Math.max(((Number)request.get("event_count")).intValue()+result.events(),(int)retained);
        int pages=((Number)request.get("page_count")).intValue()+result.pages();
        if("NOT_OBSERVED_IN_SCOPE".equals(observed)&&events>0){observed="UNAVAILABLE";coverage="PARTIAL";}
        boolean deferred=result.retryAt()!=null&&result.retryAt().isAfter(contexts.now().toInstant())&&jdbc.queryForObject("SELECT attempt_no<max_attempts FROM secret_jobs WHERE job_id=?",Boolean.class,lease.jobId());
        String completed="COMPLETE".equals(coverage)?"COMPLETE":"PARTIAL".equals(coverage)?"PARTIAL":"UNAVAILABLE";
        jdbc.update("UPDATE secret_usage_requests SET status=?,observation_status=?,coverage_status=?,binding_level=?,reason_codes=?::text[],page_count=?,event_count=?,available_from=clock_timestamp()-interval '90 days',completed_at=CASE WHEN ? THEN NULL ELSE clock_timestamp() END WHERE request_id=?",deferred?"PENDING":completed,observed,coverage,exact||hasObserved?"EXACT_CREDENTIAL":"UNRESOLVED",array(result.reasonCodes()),pages,events,deferred,lease.requestId());
        String reason=result.reasonCodes().isEmpty()?null:result.reasonCodes().getFirst();
        if(deferred)jdbc.update("UPDATE secret_jobs SET status='PENDING',available_at=?,lease_owner=NULL,lease_token=NULL,lease_until=NULL,last_error_code=? WHERE job_id=?",result.retryAt().atOffset(ZoneOffset.UTC),reason,lease.jobId());
        else finish(lease,"UNAVAILABLE".equals(completed)?"FAILED":"SUCCEEDED",reason);return !deferred&&"COMPLETE".equals(completed);
    }));}
    private Object array(List<String> values){return "{"+String.join(",",values)+"}";}
    private void lockBaseline(Map<String,Object> request){
        var c=contexts.occurrence(number(request,"occurrence_id"));var t=contexts.target(number(request,"target_id"));
        jdbc.queryForObject("SELECT occurrence_id FROM secret_occurrences WHERE occurrence_id=? FOR SHARE",Long.class,number(c,"occurrence_id"));
        jdbc.queryForObject("SELECT credential_set_id FROM secret_credential_sets WHERE credential_set_id=? FOR SHARE",Long.class,number(c,"credential_set_id"));
        jdbc.queryForList("SELECT connection_id FROM secret_connections WHERE connection_id IN(?,?) ORDER BY connection_id FOR SHARE",number(c,"connection_id"),number(t,"collector_connection_id"));
        jdbc.queryForList("SELECT scope_id FROM secret_connection_scopes WHERE scope_id IN(?,?) ORDER BY scope_id FOR SHARE",number(c,"scope_id"),number(t,"collector_scope_id"));
        jdbc.queryForObject("SELECT target_id FROM secret_usage_targets WHERE target_id=? FOR SHARE",Long.class,number(t,"target_id"));
        jdbc.queryForList("SELECT grant_id FROM secret_role_grants WHERE user_id IN(?,?) AND revoked_at IS NULL FOR SHARE",number(request,"requested_by_user_id"),number(t,"approved_by_user_id"));
    }
    private boolean owned(Lease l){return Boolean.TRUE.equals(jdbc.queryForObject("SELECT status='LEASED' AND lease_token=? AND lease_generation=? AND lease_until>clock_timestamp() FROM secret_jobs WHERE job_id=? AND purpose='USAGE_OBSERVATION'",Boolean.class,l.token(),l.generation(),l.jobId()));}
    private boolean renew(Lease l){return jdbc.update("UPDATE secret_jobs SET lease_until=clock_timestamp()+(?*interval '1 millisecond') WHERE job_id=? AND purpose='USAGE_OBSERVATION' AND status='LEASED' AND lease_token=? AND lease_generation=? AND lease_until>clock_timestamp()",properties.leaseDuration().toMillis(),l.jobId(),l.token(),l.generation())==1;}
    private void cancel(Lease l,String reason){tx.executeWithoutResult(s->{if(owned(l)){jdbc.update("UPDATE secret_usage_requests SET status='CANCELLED',observation_status='UNAVAILABLE',coverage_status='UNKNOWN',reason_codes=ARRAY[?]::text[],completed_at=clock_timestamp() WHERE request_id=?",reason,l.requestId());finish(l,"CANCELLED",reason);}});}
    private boolean finish(Lease l,String state,String reason){return jdbc.update("UPDATE secret_jobs SET status=?,last_error_code=?,finished_at=clock_timestamp(),lease_owner=NULL,lease_token=NULL,lease_until=NULL WHERE job_id=? AND status='LEASED' AND lease_token=? AND lease_generation=? AND lease_until>clock_timestamp()",state,reason,l.jobId(),l.token(),l.generation())==1;}
    private static void sleep(Duration duration){try{Thread.sleep(duration);}catch(InterruptedException e){Thread.currentThread().interrupt();throw new ContextChanged();}}
    private static final class ContextChanged extends RuntimeException{ContextChanged(){super("USAGE_BASELINE_CHANGED",null,false,false);}}
}
