package com.logssey.secret.usage.core;

import static com.logssey.secret.permission.core.SecretPermissionContext.*;
import com.logssey.secret.permission.core.SecretPermissionContext;
import java.time.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.json.JsonMapper;

/** Shared enqueue/lease/commit boundary. No credential values are selected or accepted here. */
public final class SecretUsageContext {
    private static final JsonMapper JSON=JsonMapper.builder().findAndAddModules().build();
    private final JdbcTemplate jdbc;
    public SecretUsageContext(JdbcTemplate jdbc){this.jdbc=jdbc;}
    public Map<String,Object> occurrence(long id){
        var c=new LinkedHashMap<>(new SecretPermissionContext(jdbc).read(id));
        var key=jdbc.queryForMap("SELECT aws_key_id_fingerprint,external_key_ref,fingerprint_key_version FROM secret_credential_sets WHERE credential_set_id=?",number(c,"credential_set_id"));
        c.putAll(key);return c;
    }
    public Map<String,Object> target(long id){
        var rows=jdbc.queryForList("""
SELECT t.*,c.status AS collector_status,c.provider AS collector_provider,c.auth_ref AS current_collector_auth_ref,
 c.scope_version AS current_collector_scope_version,c.display_name,
 s.connection_id AS scope_connection_id,s.enabled AS collector_scope_enabled,s.revision AS current_collector_scope_revision,
 s.content_type AS collector_content_type,s.approved_ref AS current_collector_approved_ref,s.history_limit AS collector_history_limit
FROM secret_usage_targets t JOIN secret_connections c ON c.connection_id=t.collector_connection_id
JOIN secret_connection_scopes s ON s.scope_id=t.collector_scope_id WHERE t.target_id=?
""",id);
        if(rows.isEmpty())throw new IllegalArgumentException("TARGET_UNAVAILABLE");return rows.getFirst();
    }
    public static String sourceVersion(Map<String,Object> c){
        var fields=new TreeMap<String,Object>();
        for(String key:List.of("occurrence_id","credential_set_id","credential_revision","scope_id","scope_revision","scope_version","latest_object_version","response_origin_version","scope_enabled","connection_status","auth_ref","approved_ref","content_type","history_limit"))fields.put(key,Objects.toString(c.get(key),""));
        return digest(JSON.writeValueAsString(fields));
    }
    public static Map<String,Object> baseline(Map<String,Object> c,Map<String,Object> t){
        return facts("sourceContextVersion",sourceVersion(c),"targetRevision",t.get("revision"),
            "collectorScopeVersion",t.get("current_collector_scope_version"),"collectorAuthRef",t.get("current_collector_auth_ref"),
            "collectorScopeId",t.get("collector_scope_id"),"collectorScopeRevision",t.get("current_collector_scope_revision"),
            "collectorApprovedRef",t.get("current_collector_approved_ref"),"accountRef",t.get("account_ref"),"region",t.get("region"));
    }
    public List<String> targetReasons(Map<String,Object> c,Map<String,Object> t){
        var reasons=new ArrayList<String>();
        if(number(c,"occurrence_id")!=number(t,"occurrence_id"))reasons.add("TARGET_MISMATCH");
        if(!"AWS".equals(c.get("issuer"))||!Set.of("AWS_ACCESS_KEY_PAIR","AWS_IAM_ACCESS_KEY","AWS_TEMPORARY_CREDENTIALS").contains(c.get("credential_type")))reasons.add("PROVIDER_USAGE_UNSUPPORTED");
        if(!"ACTIVE".equals(c.get("connection_status"))||!Boolean.TRUE.equals(c.get("scope_enabled")))reasons.add("SOURCE_UNAVAILABLE");
        if(!Boolean.TRUE.equals(t.get("enabled")))reasons.add("TARGET_DISABLED");
        if(number(c,"credential_revision")!=number(t,"credential_revision")||number(c,"scope_revision")!=number(t,"scope_revision")||number(c,"scope_version")!=number(t,"source_scope_version"))reasons.add("SOURCE_APPROVAL_CHANGED");
        if(!"ACTIVE".equals(t.get("collector_status"))||!"AWS".equals(t.get("collector_provider"))||!Boolean.TRUE.equals(t.get("collector_scope_enabled"))
            ||number(t,"scope_connection_id")!=number(t,"collector_connection_id")
            ||number(t,"collector_scope_version")!=number(t,"current_collector_scope_version")
            ||number(t,"collector_scope_revision")!=number(t,"current_collector_scope_revision")
            ||!Objects.equals(t.get("collector_auth_ref"),t.get("current_collector_auth_ref"))
            ||!Objects.equals(t.get("collector_approved_ref"),t.get("current_collector_approved_ref"))
            ||!"IAM_ACCESS_KEY_METADATA".equals(t.get("collector_content_type"))
            ||!Objects.equals("aws://"+t.get("account_ref")+"/global/iam/access-keys",t.get("current_collector_approved_ref"))
            ||(t.get("collector_history_limit")!=null&&!"CURRENT_STATE_ONLY".equals(t.get("collector_history_limit"))))reasons.add("COLLECTOR_APPROVAL_CHANGED");
        if(!requesterAuthorized(number(t,"approved_by_user_id"),c,t))reasons.add("TARGET_APPROVER_NOT_AUTHORIZED");
        if(c.get("account_ref")!=null&&!Objects.equals(c.get("account_ref"),t.get("account_ref")))reasons.add("IDENTITY_BINDING_UNRESOLVED");
        return reasons;
    }
    public static String keyIdentifierStatus(Map<String,Object> c){
        if("AWS_IAM_ACCESS_KEY".equals(c.get("credential_type"))&&c.get("external_key_ref")!=null)return "PROTECTED_REFERENCE_AVAILABLE";
        if("AWS_ACCESS_KEY_PAIR".equals(c.get("credential_type"))&&c.get("aws_key_id_fingerprint") instanceof byte[] bytes&&bytes.length==32)return "PROTECTED_REFERENCE_AVAILABLE";
        return "KEY_IDENTIFIER_UNAVAILABLE";
    }
    public boolean requesterAuthorized(long user,Map<String,Object> c,Map<String,Object> t){
        return Boolean.TRUE.equals(jdbc.queryForObject("""
SELECT EXISTS(SELECT 1 FROM secret_role_grants WHERE user_id=? AND role='SECURITY' AND revoked_at IS NULL AND(connection_id IS NULL OR connection_id=?))
AND EXISTS(SELECT 1 FROM secret_role_grants WHERE user_id=? AND role IN('SECURITY','OPERATIONS') AND revoked_at IS NULL AND(connection_id IS NULL OR connection_id=?))
""",Boolean.class,user,number(c,"connection_id"),user,number(t,"collector_connection_id")));
    }
    public boolean current(Map<String,Object> request){
        try{
            var c=occurrence(number(request,"occurrence_id"));var t=target(number(request,"target_id"));
            if(!targetReasons(c,t).isEmpty()||!requesterAuthorized(number(request,"requested_by_user_id"),c,t))return false;
            var expected=JSON.readValue(request.get("baseline").toString(),Map.class);
            var actual=baseline(c,t);
            return expected.keySet().equals(actual.keySet())&&actual.entrySet().stream().allMatch(e->Objects.toString(e.getValue(),"").equals(Objects.toString(expected.get(e.getKey()),"")));
        }catch(IllegalArgumentException missing){return false;}
    }
    /** Caller holds a transaction plus source/target row locks. Rechecked again before any provider I/O and persistence. */
    public long enqueue(Map<String,Object> c,Map<String,Object> t,long user,OffsetDateTime start,OffsetDateTime end,String trigger){
        if(!targetReasons(c,t).isEmpty()||!requesterAuthorized(user,c,t))throw new IllegalArgumentException("USAGE_CONTEXT_CHANGED");
        var b=baseline(c,t);
        long job=jdbc.queryForObject("""
INSERT INTO secret_jobs(kind,purpose,connection_id,target_occurrence_id,requested_by_user_id,idempotency_key,expected_context,scheduled_at,available_at,attempt_no,max_attempts,status)
VALUES('ENRICH','USAGE_OBSERVATION',?,?,?, ?,?::jsonb,clock_timestamp(),clock_timestamp(),0,3,'PENDING') RETURNING job_id
""",Long.class,number(c,"connection_id"),number(c,"occurrence_id"),user,"usage:"+UUID.randomUUID(),JSON.writeValueAsString(b));
        return jdbc.queryForObject("""
INSERT INTO secret_usage_requests(job_id,target_id,occurrence_id,credential_set_id,credential_revision,scope_revision,requested_by_user_id,trigger_type,source_context_version,baseline,window_start,window_end)
VALUES(?,?,?,?,?,?,?,?,?,?::jsonb,?,?) RETURNING request_id
""",Long.class,job,number(t,"target_id"),number(c,"occurrence_id"),number(c,"credential_set_id"),number(c,"credential_revision"),number(c,"scope_revision"),user,trigger,sourceVersion(c),JSON.writeValueAsString(b),start,end);
    }
    public Map<String,Object> request(long id){
        var rows=jdbc.queryForList("SELECT * FROM secret_usage_requests WHERE request_id=?",id);
        if(rows.isEmpty())throw new IllegalArgumentException("REQUEST_UNAVAILABLE");return rows.getFirst();
    }
    public OffsetDateTime now(){return jdbc.queryForObject("SELECT clock_timestamp()",OffsetDateTime.class);}
}
