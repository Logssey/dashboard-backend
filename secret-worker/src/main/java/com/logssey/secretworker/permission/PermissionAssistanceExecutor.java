package com.logssey.secretworker.permission;

import static com.logssey.secret.permission.core.SecretPermissionContext.*;
import com.logssey.secret.permission.core.SecretPermissionContext;
import com.logssey.secret.aws.SecretAwsSourceCredentials;
import com.logssey.secretworker.SecretJobProperties;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.json.JsonMapper;

/** ENRICH uses the common leased job ledger. It has no ScanRun and never records scan coverage. */
@Service
public class PermissionAssistanceExecutor {
    public record Lease(long jobId,long requestId,long occurrenceId,UUID token,long generation){}
    private final JdbcTemplate jdbc;private final TransactionTemplate tx;private final SecretPermissionContext contexts;private final SecretJobProperties properties;
    private final ObjectProvider<SecretAwsSourceCredentials> credentials;private final JsonMapper json=JsonMapper.builder().findAndAddModules().build();
    private final AwsPermissionObserver aws;
    @org.springframework.beans.factory.annotation.Autowired
    public PermissionAssistanceExecutor(JdbcTemplate jdbc,PlatformTransactionManager manager,SecretJobProperties properties,ObjectProvider<SecretAwsSourceCredentials> credentials){this(jdbc,manager,properties,credentials,new AwsPermissionObserver());}
    public PermissionAssistanceExecutor(JdbcTemplate jdbc,PlatformTransactionManager manager,SecretJobProperties properties,ObjectProvider<SecretAwsSourceCredentials> credentials,AwsPermissionObserver aws){this.jdbc=jdbc;this.tx=new TransactionTemplate(manager);this.contexts=new SecretPermissionContext(jdbc);this.properties=properties;this.credentials=credentials;this.aws=aws;}

    public Optional<Lease> claim(){return tx.execute(status->{
        jdbc.update("UPDATE secret_jobs SET status=CASE WHEN attempt_no>=max_attempts THEN 'FAILED' ELSE 'PENDING' END,finished_at=CASE WHEN attempt_no>=max_attempts THEN clock_timestamp() ELSE NULL END,available_at=clock_timestamp(),lease_owner=NULL,lease_token=NULL,lease_until=NULL,last_error_code='PERMISSION_LEASE_EXPIRED' WHERE kind='ENRICH' AND status='LEASED' AND lease_until<=clock_timestamp()");
        var rows=jdbc.queryForList("SELECT j.job_id,j.target_occurrence_id,j.lease_generation,r.request_id FROM secret_jobs j JOIN secret_permission_requests r USING(job_id) WHERE j.kind='ENRICH' AND j.purpose='PERMISSION_ASSISTANCE' AND j.status='PENDING' AND j.available_at<=clock_timestamp() AND j.attempt_no<j.max_attempts ORDER BY j.available_at,j.job_id LIMIT 1 FOR UPDATE OF j SKIP LOCKED");
        if(rows.isEmpty())return Optional.empty();var r=rows.getFirst();UUID token=UUID.randomUUID();long generation=number(r,"lease_generation")+1;
        jdbc.update("UPDATE secret_jobs SET status='LEASED',lease_owner=?,lease_token=?,lease_generation=?,lease_until=clock_timestamp()+(?*interval '1 millisecond'),attempt_no=attempt_no+1,last_error_code=NULL WHERE job_id=?",token.toString(),token,generation,properties.leaseDuration().toMillis(),number(r,"job_id"));
        return Optional.of(new Lease(number(r,"job_id"),number(r,"request_id"),number(r,"target_occurrence_id"),token,generation));
    });}
    public boolean execute(Lease lease){
        var lost=new AtomicBoolean();var thread=Executors.newSingleThreadScheduledExecutor(Thread.ofVirtual().name("permission-lease-heartbeat").factory());
        var timer=thread.scheduleWithFixedDelay(()->{try{if(!renew(lease))lost.set(true);}catch(RuntimeException failure){lost.set(true);}},Math.max(1000,properties.leaseDuration().toMillis()/3),Math.max(1000,properties.leaseDuration().toMillis()/3),TimeUnit.MILLISECONDS);
        try{
            var request=request(lease);var c=preflight(lease,request);if(c==null){cancel(lease,"PERMISSION_BASELINE_CHANGED");return false;}
            PermissionCandidate candidate;
            if("AWS".equals(c.get("issuer"))){var source=credentials.getIfAvailable();if(source==null||!source.authRef().equals(request.get("collector_auth_ref")))candidate=PermissionCandidate.unavailable("COLLECTOR_NOT_CONFIGURED");
                else candidate=aws.observe(c,source,()->{if(lost.get()||preflight(lease,request)==null||!renew(lease))throw new IllegalStateException("PERMISSION_BASELINE_CHANGED");});}
            else if("GITHUB".equals(c.get("issuer")))candidate=new PermissionCapabilityNormalizer().github(json.readValue(c.get("identity_claims").toString(),Map.class));
            else candidate=PermissionCandidate.unsupported("UNSUPPORTED_TYPE");
            if(lost.get())return false;
            var finalCandidate=candidate;
            return Boolean.TRUE.equals(tx.execute(status->{
                if(preflight(lease,request)==null){cancel(lease,"PERMISSION_BASELINE_CHANGED");return false;}
                jdbc.queryForObject("SELECT job_id FROM secret_jobs WHERE job_id=? FOR UPDATE",Long.class,lease.jobId());if(!owned(lease))return false;
                var now=jdbc.queryForObject("SELECT clock_timestamp()",OffsetDateTime.class);var expiry=now.plusHours(6);var identityExpiry=time(c.get("identity_expires_at"));if(identityExpiry.isBefore(expiry))expiry=identityExpiry;
                if(!expiry.isAfter(now)){cancel(lease,"IDENTITY_OBSERVATION_EXPIRED");return false;}
                var sourceObserved="GITHUB".equals(c.get("issuer"))?time(c.get("identity_observed_at")):now;
                var safeFacts=new LinkedHashMap<String,Object>(finalCandidate.facts());safeFacts.put("sourceBasis","GITHUB".equals(c.get("issuer"))?"RECENT_VALIDATION_METADATA":"APPROVED_IAM_POLICY_METADATA");
                jdbc.update("INSERT INTO secret_permission_observations(request_id,status,safe_facts,observed_at,expires_at,observer_version) VALUES(?,?,?::jsonb,?,?,'permission-assistance-v1') ON CONFLICT(request_id) DO NOTHING",lease.requestId(),finalCandidate.status(),json.writeValueAsString(safeFacts),sourceObserved,expiry);
                if(!finish(lease,"SUCCEEDED",null))throw new IllegalStateException("PERMISSION_LEASE_LOST");return true;
            }));
        }catch(RuntimeException failure){
            tx.executeWithoutResult(status->jdbc.update("UPDATE secret_jobs SET status=CASE WHEN attempt_no>=max_attempts THEN 'FAILED' ELSE 'PENDING' END,finished_at=CASE WHEN attempt_no>=max_attempts THEN clock_timestamp() ELSE NULL END,available_at=clock_timestamp()+interval '30 seconds',last_error_code='PERMISSION_OBSERVER_FAILED',lease_owner=NULL,lease_token=NULL,lease_until=NULL WHERE job_id=? AND status='LEASED' AND lease_token=? AND lease_generation=? AND lease_until>clock_timestamp()",lease.jobId(),lease.token(),lease.generation()));return false;
        }finally{timer.cancel(true);thread.shutdownNow();}
    }
    private Map<String,Object> request(Lease lease){var rows=jdbc.queryForList("SELECT r.*,r.baseline::text AS baseline_json,c.auth_ref AS collector_auth_ref FROM secret_permission_requests r JOIN secret_connections c ON c.connection_id=r.collector_connection_id WHERE r.request_id=? AND r.job_id=?",lease.requestId(),lease.jobId());if(rows.isEmpty())throw new IllegalStateException("PERMISSION_REQUEST_MISSING");return rows.getFirst();}
    private Map<String,Object> preflight(Lease lease,Map<String,Object> request){
        if(!owned(lease))return null;var c=contexts.read(lease.occurrenceId());var baseline=json.readValue(request.get("baseline_json").toString(),Map.class);
        if(c.get("identity_id")==null||!Objects.equals(baseline.get("sourceContextVersion"),sourceVersion(c))||number(c,"identity_id")!=number(request,"identity_id")||!"ACTIVE".equals(c.get("connection_status"))||!Boolean.TRUE.equals(c.get("scope_enabled")))return null;
        long actor=number(request,"requested_by_user_id"),collector=number(request,"collector_connection_id");
        boolean allowed=Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM secret_role_grants WHERE user_id=? AND role='SECURITY' AND revoked_at IS NULL AND(connection_id IS NULL OR connection_id=?)) AND EXISTS(SELECT 1 FROM secret_role_grants WHERE user_id=? AND role IN('SECURITY','OPERATIONS') AND revoked_at IS NULL AND(connection_id IS NULL OR connection_id=?))",Boolean.class,actor,number(c,"connection_id"),actor,collector));if(!allowed)return null;
        var scopes=jdbc.queryForList("SELECT c.auth_ref,c.scope_version,s.scope_id,s.revision,s.approved_ref,c.provider FROM secret_connections c JOIN secret_connection_scopes s USING(connection_id) WHERE c.connection_id=? AND s.scope_id=? AND c.status='ACTIVE' AND s.enabled",collector,Long.parseLong(baseline.get("collectorScopeId").toString()));
        if(scopes.isEmpty())return null;var source=scopes.getFirst();
        for(var pair:Map.of("collectorAuthRef","auth_ref","collectorScopeVersion","scope_version","collectorScopeRevision","revision","collectorApprovedRef","approved_ref").entrySet())if(!Objects.toString(baseline.get(pair.getKey()),"").equals(Objects.toString(source.get(pair.getValue()),"")))return null;
        if("AWS".equals(c.get("issuer"))&&(!"AWS".equals(source.get("provider"))||!("aws://"+c.get("account_ref")+"/global/iam/access-keys").equals(source.get("approved_ref"))))return null;
        if("GITHUB".equals(c.get("issuer"))&&(collector!=number(c,"connection_id")||!"GITHUB".equals(source.get("provider"))))return null;
        return c;
    }
    private boolean owned(Lease lease){return Boolean.TRUE.equals(jdbc.queryForObject("SELECT status='LEASED' AND lease_token=? AND lease_generation=? AND lease_until>clock_timestamp() FROM secret_jobs WHERE job_id=? AND kind='ENRICH'",Boolean.class,lease.token(),lease.generation(),lease.jobId()));}
    private boolean renew(Lease lease){return jdbc.update("UPDATE secret_jobs SET lease_until=clock_timestamp()+(?*interval '1 millisecond') WHERE job_id=? AND kind='ENRICH' AND status='LEASED' AND lease_token=? AND lease_generation=? AND lease_until>clock_timestamp()",properties.leaseDuration().toMillis(),lease.jobId(),lease.token(),lease.generation())==1;}
    private void cancel(Lease lease,String reason){tx.executeWithoutResult(status->{if(owned(lease))finish(lease,"CANCELLED",reason);});}
    private boolean finish(Lease lease,String status,String reason){return jdbc.update("UPDATE secret_jobs SET status=?,last_error_code=?,finished_at=clock_timestamp(),lease_owner=NULL,lease_token=NULL,lease_until=NULL WHERE job_id=? AND status='LEASED' AND lease_token=? AND lease_generation=? AND lease_until>clock_timestamp()",status,reason,lease.jobId(),lease.token(),lease.generation())==1;}
}
