package com.logssey.secret.usage;

import static com.logssey.secret.permission.core.SecretPermissionContext.facts;
import static com.logssey.secret.permission.core.SecretPermissionContext.number;
import static com.logssey.secret.permission.core.SecretPermissionContext.time;
import static com.logssey.secret.usage.SecretUsageContracts.*;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.risk.SecretRiskCommands;
import com.logssey.secret.usage.core.SecretUsageContext;
import java.time.*;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.json.JsonMapper;

/** Usage facts and review history have no write path into severity-v2 or abuse evidence. */
@Service
public class SecretUsageService {
    private static final Set<String> ACTIONS=Set.of("API_CALL","RESOURCE_READ","RESOURCE_CHANGE","AUTHENTICATION","UNKNOWN");
    private static final Set<String> RESULTS=Set.of("SUCCESS","FAILURE","UNKNOWN");
    private static final Set<String> REASONS=Set.of("REVIEWED_USAGE","INSUFFICIENT_EVIDENCE","IDENTITY_MISMATCH","WITHDRAWN_BY_REVIEWER");
    private final JdbcTemplate jdbc;
    private final SecretAccessService access;
    private final SecretRiskCommands commands;
    private final SecretUsageContext contexts;
    private final boolean enabled;
    private final JsonMapper json=JsonMapper.builder().findAndAddModules().build();
    public SecretUsageService(JdbcTemplate jdbc,SecretAccessService access,SecretRiskCommands commands,@Value("${logssey.secret.usage.cloudtrail-enabled:${SECRET_USAGE_CLOUDTRAIL_ENABLED:false}}")boolean enabled){
        this.jdbc=jdbc;this.access=access;this.commands=commands;this.contexts=new SecretUsageContext(jdbc);this.enabled=enabled;
    }

    @Transactional(readOnly=true)
    public Map<String,Object> read(String login,long credential,long occurrence,int page,int size){
        if(page<1||size<1||size>100||page>100000)throw invalid();
        var actor=reader(login,occurrence);var c=current(occurrence,credential);
        var targets=targets(actor,c);var blocked=readiness(actor,c,targets);
        var latestRows=jdbc.queryForList("SELECT request_id,target_id FROM secret_usage_requests WHERE occurrence_id=? ORDER BY request_id DESC",occurrence);
        Map<String,Object> latest=null;
        for(var row:latestRows){var t=contexts.target(number(row,"target_id"));if(access.canReadConnectionFacts(actor,number(t,"collector_connection_id"))){latest=publicRequest(contexts.request(number(row,"request_id")),c,t);break;}}
        var filter=observationFilter(actor,c,targets);
        long count=jdbc.queryForObject("SELECT count(*) FROM secret_usage_observations u WHERE "+filter.sql(),Long.class,filter.args().toArray());
        var args=new ArrayList<Object>(filter.args());args.add(size);args.add((page-1)*size);
        var observations=jdbc.queryForList("SELECT u.* FROM secret_usage_observations u WHERE "+filter.sql()+" ORDER BY u.event_at DESC,u.observation_id DESC LIMIT ? OFFSET ?",args.toArray()).stream().map(row->publicObservation(actor,c,row)).toList();
        String observationStatus=latest==null?"NOT_REQUESTED":Objects.toString(latest.get("observationStatus"),"UNAVAILABLE");
        return facts("credentialId",credential,"occurrenceId",occurrence,"credentialRevision",c.get("credential_revision"),"scopeRevision",c.get("scope_revision"),
            "support",facts("status",supported(c)?"PARTIAL":"UNSUPPORTED","reasonCodes",supported(c)?List.of("MANAGEMENT_EVENTS_ONLY","IAM_METADATA_IS_SEPARATE"):List.of("PROVIDER_USAGE_UNSUPPORTED")),
            "capabilities",facts("canRequest",blocked.isEmpty(),"canSubmit",canSubmit(actor,c),"blockedReasonCodes",blocked),
            "keyIdentifierStatus",SecretUsageContext.keyIdentifierStatus(c),
            "targetOptions",targets.stream().map(this::publicTarget).toList(),"availableSourceRefs",sourceRefs(actor,c),"availableTargetRefs",targetRefs(c),
            "latestRequest",latest,"observationStatus",observationStatus,"iamLastUsed",iamMetadata(actor,c),
            "observations",facts("items",observations,"page",page,"pageSize",size,"totalElements",count));
    }

    public Map<String,Object> request(String login,long credential,Request body){
        if(body==null||body.occurrenceId()==null||body.serverRegisteredTargetId()==null)throw invalid();
        var actor=reader(login,body.occurrenceId());current(body.occurrenceId(),credential);
        var result=commands.execute(actor,"USAGE_REQUESTED",body.idempotencyKey(),facts("credentialId",credential,"body",body),()->{
            var c=lock(body.occurrenceId(),credential);security(actor,c);revisions(c,body.expectedCredentialRevision(),body.expectedScopeRevision());
            var t=lockTarget(actor,body.serverRegisteredTargetId());if(!contexts.targetReasons(c,t).isEmpty())throw conflict();
            if(!enabled)throw new ApiException(ErrorCode.UNPROCESSABLE);
        },()->{
            var c=current(body.occurrenceId(),credential);var t=contexts.target(body.serverRegisteredTargetId());
            if(!readiness(actor,c,List.of(t)).isEmpty())throw new ApiException(ErrorCode.UNPROCESSABLE);
            var now=contexts.now();var end=body.windowEnd()==null?now:body.windowEnd();var start=body.windowStart()==null?end.minusDays(7):body.windowStart();window(start,end,now);
            if(Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM secret_jobs WHERE target_occurrence_id=? AND purpose='USAGE_OBSERVATION' AND status IN('PENDING','LEASED'))",Boolean.class,body.occurrenceId())))throw conflict();
            long recent=jdbc.queryForObject("SELECT count(*) FROM secret_usage_requests WHERE requested_by_user_id=? AND requested_at>clock_timestamp()-interval '1 minute'",Long.class,actor.userId());if(recent>=10)throw new ApiException(ErrorCode.UNPROCESSABLE);
            long id=contexts.enqueue(c,t,actor.userId(),start,end,"MANUAL");
            return facts("requestId",id,"occurrenceId",body.occurrenceId(),"evidenceRevision",c.get("risk_evidence_revision"));
        });
        return status(login,((Number)result.get("requestId")).longValue());
    }

    @Transactional(readOnly=true)
    public Map<String,Object> status(String login,long id){
        var r=requestRow(id);var actor=reader(login,number(r,"occurrence_id"));var c=current(number(r,"occurrence_id"),number(r,"credential_set_id"));
        var t=contexts.target(number(r,"target_id"));access.requireConnectionFactsRead(actor,number(t,"collector_connection_id"));
        return publicRequest(r,c,t);
    }

    public Map<String,Object> submit(String login,long credential,Manual body){
        if(body==null||body.occurrenceId()==null||body.sourceRef()==null||body.targetRef()==null||body.eventAt()==null||body.actionCode()==null||body.actionResult()==null
            ||!ACTIONS.contains(body.actionCode())||!RESULTS.contains(body.actionResult())||!Set.of("UNATTRIBUTED","EXPECTED_WORKLOAD").contains(Objects.toString(body.actorAttribution(),"")))throw invalid();
        var actor=reader(login,body.occurrenceId());current(body.occurrenceId(),credential);
        var result=commands.execute(actor,"USAGE_SUBMITTED",body.idempotencyKey(),facts("credentialId",credential,"body",body),()->{
            var c=lock(body.occurrenceId(),credential);lockSubmitter(actor,body.occurrenceId());if(!canSubmit(actor,c))throw new ApiException(ErrorCode.FORBIDDEN);
            revisions(c,body.expectedCredentialRevision(),body.expectedScopeRevision());sourceRef(actor,c,body.sourceRef());targetRef(c,body.targetRef());
            if(!"ACTIVE".equals(c.get("connection_status"))||!Boolean.TRUE.equals(c.get("scope_enabled")))throw conflict();
        },()->{
            var c=current(body.occurrenceId(),credential);window(body.windowStart(),body.windowEnd(),contexts.now());
            if(body.eventAt().isBefore(body.windowStart())||!body.eventAt().isBefore(body.windowEnd()))throw invalid();
            String binding=c.get("identity_id")==null?"UNRESOLVED":"PRINCIPAL_ONLY";
            long id=jdbc.queryForObject("""
INSERT INTO secret_usage_observations(source_kind,occurrence_id,credential_set_id,credential_revision,scope_revision,submitted_by_user_id,source_context_version,
 binding_level,coverage_status,action_code,action_result,actor_attribution,source_ref_type,source_ref_id,target_ref_type,target_ref_id,event_at,window_start,window_end)
VALUES('MANUAL',?,?,?,?,?, ?,?,'UNKNOWN',?,?,?,?,?,?,?,?,?,?) RETURNING observation_id
""",Long.class,body.occurrenceId(),credential,number(c,"credential_revision"),number(c,"scope_revision"),actor.userId(),SecretUsageContext.sourceVersion(c),binding,body.actionCode(),body.actionResult(),body.actorAttribution(),body.sourceRef().type(),body.sourceRef().id(),body.targetRef().type(),body.targetRef().id(),body.eventAt(),body.windowStart(),body.windowEnd());
            return facts("observationId",id,"occurrenceId",body.occurrenceId(),"evidenceRevision",c.get("risk_evidence_revision"));
        });
        var c=current(body.occurrenceId(),credential);return publicObservation(actor,c,observation(((Number)result.get("observationId")).longValue()));
    }

    public Map<String,Object> decide(String login,long id,Decision body){
        if(body==null||body.expectedObservationRevision()==null||!Set.of("ACCEPT","REJECT","WITHDRAW").contains(Objects.toString(body.decision(),""))||!REASONS.contains(Objects.toString(body.reasonCode(),"")))throw invalid();
        boolean validReason=switch(body.decision()){case "ACCEPT"->"REVIEWED_USAGE".equals(body.reasonCode());case "REJECT"->Set.of("INSUFFICIENT_EVIDENCE","IDENTITY_MISMATCH").contains(body.reasonCode());default->"WITHDRAWN_BY_REVIEWER".equals(body.reasonCode());};if(!validReason)throw invalid();
        var row=observation(id);var actor=reader(login,number(row,"occurrence_id"));
        var result=commands.execute(actor,"USAGE_REVIEWED",body.idempotencyKey(),facts("observationId",id,"body",body),()->{
            var c=lock(number(row,"occurrence_id"),number(row,"credential_set_id"));security(actor,c);
            if(!"MANUAL".equals(row.get("source_kind")))throw invalid();
            if(!observationCurrent(c,row))throw conflict();
            sourceRef(actor,c,new Ref((String)row.get("source_ref_type"),number(row,"source_ref_id")));targetRef(c,new Ref((String)row.get("target_ref_type"),number(row,"target_ref_id")));
        },()->{
            // The row lock serializes append-only decisions; expected revision is a CAS token.
            jdbc.queryForObject("SELECT observation_id FROM secret_usage_observations WHERE observation_id=? FOR UPDATE",Long.class,id);
            long revision=decisionRevision(id);if(revision!=body.expectedObservationRevision())throw conflict();
            var permitted=allowedDecisions(actor,current(number(row,"occurrence_id"),number(row,"credential_set_id")),row);
            if(!permitted.contains(body.decision()))throw conflict();
            jdbc.update("INSERT INTO secret_usage_decisions(observation_id,observation_revision,actor_user_id,decision,reason_code) VALUES(?,?,?,?,?)",id,revision+1,actor.userId(),body.decision(),body.reasonCode());
            var c=current(number(row,"occurrence_id"),number(row,"credential_set_id"));return facts("observationId",id,"occurrenceId",row.get("occurrence_id"),"evidenceRevision",c.get("risk_evidence_revision"));
        });
        var c=current(number(row,"occurrence_id"),number(row,"credential_set_id"));return publicObservation(actor,c,observation(((Number)result.get("observationId")).longValue()));
    }

    private List<Map<String,Object>> targets(SecretPrincipal actor,Map<String,Object> c){
        return jdbc.queryForList("SELECT target_id FROM secret_usage_targets WHERE occurrence_id=? ORDER BY target_id",number(c,"occurrence_id")).stream()
            .map(row->contexts.target(number(row,"target_id"))).filter(t->access.canReadConnectionFacts(actor,number(t,"collector_connection_id"))&&contexts.targetReasons(c,t).isEmpty()).toList();
    }
    private List<String> readiness(SecretPrincipal actor,Map<String,Object> c,List<Map<String,Object>> targets){
        var reasons=new ArrayList<String>();if(!enabled)reasons.add("USAGE_COLLECTION_DISABLED");if(!supported(c))reasons.add("PROVIDER_USAGE_UNSUPPORTED");
        if(!access.hasConnectionRole(actor,number(c,"connection_id"),SecretRole.SECURITY))reasons.add("SECURITY_REQUIRED");
        if(!"ACTIVE".equals(c.get("connection_status"))||!Boolean.TRUE.equals(c.get("scope_enabled")))reasons.add("SOURCE_UNAVAILABLE");
        if(targets.isEmpty())reasons.add("APPROVED_TARGET_REQUIRED");
        if(supported(c)&&!"PROTECTED_REFERENCE_AVAILABLE".equals(SecretUsageContext.keyIdentifierStatus(c)))reasons.add("KEY_IDENTIFIER_UNAVAILABLE");
        else if("AWS_ACCESS_KEY_PAIR".equals(c.get("credential_type"))){
            if(c.get("identity_id")==null)reasons.add("FRESH_IDENTITY_VALIDATION_REQUIRED");
            else if(!"IAM_USER".equals(c.get("principal_type")))reasons.add("KEY_IDENTIFIER_UNAVAILABLE");
        }
        return reasons;
    }
    private boolean supported(Map<String,Object> c){return "AWS".equals(c.get("issuer"))&&Set.of("AWS_ACCESS_KEY_PAIR","AWS_IAM_ACCESS_KEY","AWS_TEMPORARY_CREDENTIALS").contains(c.get("credential_type"));}
    private Map<String,Object> publicTarget(Map<String,Object> t){String account=(String)t.get("account_ref");return facts("targetId",t.get("target_id"),"displayName","AWS · "+t.get("region"),"accountRef","계정 · …"+account.substring(8),"region",t.get("region"),"scheduleEnabled",t.get("schedule_enabled"));}
    private Map<String,Object> publicRequest(Map<String,Object> r,Map<String,Object> c,Map<String,Object> t){
        boolean valid=contexts.current(r);var job=jdbc.queryForMap("SELECT status,last_error_code,finished_at FROM secret_jobs WHERE job_id=?",r.get("job_id"));
        String status=(String)r.get("status");if("PENDING".equals(status)&&"LEASED".equals(job.get("status")))status="RUNNING";
        if(Set.of("PENDING","RUNNING").contains(status)&&Set.of("DEAD","CANCELLED","FAILED").contains(job.get("status")))status="UNAVAILABLE";
        if(!valid&&Set.of("PENDING","RUNNING").contains(status))status="CANCELLED";
        return facts("requestId",r.get("request_id"),"credentialId",r.get("credential_set_id"),"occurrenceId",r.get("occurrence_id"),"evidenceRevision",c.get("risk_evidence_revision"),
            "status",status,"observationStatus",valid?r.get("observation_status"):"UNAVAILABLE","coverageStatus",valid?r.get("coverage_status"):"UNKNOWN","bindingLevel",valid?r.get("binding_level"):"UNRESOLVED",
            "reasonCodes",valid?array(r.get("reason_codes")):List.of("CONTEXT_CHANGED"),"windowStart",time(r.get("window_start")),"windowEnd",time(r.get("window_end")),"availableFrom",time(r.get("available_from")),
            "requestedAt",time(r.get("requested_at")),"startedAt",time(r.get("started_at")),"completedAt",time(r.get("completed_at")),"pageCount",valid?r.get("page_count"):0,"eventCount",valid?r.get("event_count"):0,
            "target",publicTarget(t),"currentApplicable",valid,"triggerType",r.get("trigger_type"));
    }
    private record Filter(String sql,List<Object> args){}
    private Filter observationFilter(SecretPrincipal actor,Map<String,Object> c,List<Map<String,Object>> targets){
        var args=new ArrayList<Object>();args.add(number(c,"occurrence_id"));StringBuilder sql=new StringBuilder("u.occurrence_id=? AND ((u.source_kind='MANUAL' AND "+sourceVisibility("u",actor,c)+")");
        for(var t:targets){
            var latest=jdbc.queryForList("""
SELECT r.window_start,r.window_end FROM secret_usage_requests r WHERE r.target_id=? AND r.baseline=?::jsonb
 AND EXISTS(SELECT 1 FROM secret_role_grants g WHERE g.user_id=r.requested_by_user_id AND g.revoked_at IS NULL AND g.role='SECURITY' AND(g.connection_id IS NULL OR g.connection_id=?))
 AND EXISTS(SELECT 1 FROM secret_role_grants g WHERE g.user_id=r.requested_by_user_id AND g.revoked_at IS NULL AND g.role IN('SECURITY','OPERATIONS') AND(g.connection_id IS NULL OR g.connection_id=?))
 ORDER BY r.request_id DESC LIMIT 1
""",number(t,"target_id"),json.writeValueAsString(SecretUsageContext.baseline(c,t)),number(c,"connection_id"),number(t,"collector_connection_id"));
            if(latest.isEmpty())continue;
            sql.append(" OR (u.source_kind='PROVIDER' AND u.event_at>=? AND u.event_at<=? AND EXISTS(SELECT 1 FROM secret_usage_requests r WHERE r.request_id=u.request_id AND r.target_id=? AND r.baseline=?::jsonb AND ")
               .append("EXISTS(SELECT 1 FROM secret_role_grants g WHERE g.user_id=r.requested_by_user_id AND g.revoked_at IS NULL AND g.role='SECURITY' AND(g.connection_id IS NULL OR g.connection_id=?)) AND ")
               .append("EXISTS(SELECT 1 FROM secret_role_grants g WHERE g.user_id=r.requested_by_user_id AND g.revoked_at IS NULL AND g.role IN('SECURITY','OPERATIONS') AND(g.connection_id IS NULL OR g.connection_id=?))))");
            args.add(time(latest.getFirst().get("window_start")));args.add(time(latest.getFirst().get("window_end")));args.add(number(t,"target_id"));args.add(json.writeValueAsString(SecretUsageContext.baseline(c,t)));args.add(number(c,"connection_id"));args.add(number(t,"collector_connection_id"));
        }
        sql.append(')');return new Filter(sql.toString(),args);
    }
    private Map<String,Object> publicObservation(SecretPrincipal actor,Map<String,Object> c,Map<String,Object> row){
        if("MANUAL".equals(row.get("source_kind"))&&!sourceVisible(actor,c,new Ref((String)row.get("source_ref_type"),number(row,"source_ref_id"))))throw new ApiException(ErrorCode.NOT_FOUND);
        long id=number(row,"observation_id");var decisions=jdbc.queryForList("SELECT observation_revision,decision,reason_code,created_at FROM secret_usage_decisions WHERE observation_id=? ORDER BY observation_revision",id);
        String review="PROVIDER".equals(row.get("source_kind"))?"NOT_REQUIRED":decisions.isEmpty()?"PENDING":switch((String)decisions.getLast().get("decision")){case "ACCEPT"->"ACCEPTED";case "REJECT"->"REJECTED";default->"WITHDRAWN";};
        return facts("observationId",id,"credentialId",row.get("credential_set_id"),"occurrenceId",row.get("occurrence_id"),"evidenceRevision",c.get("risk_evidence_revision"),
            "sourceKind",row.get("source_kind"),"bindingLevel",row.get("binding_level"),"coverageStatus",row.get("coverage_status"),"actionCode",row.get("action_code"),"operationCode",row.get("operation_code"),"actionResult",row.get("action_result"),"actorAttribution",row.get("actor_attribution"),"serviceCode",row.get("service_code"),
            "eventAt",time(row.get("event_at")),"windowStart",time(row.get("window_start")),"windowEnd",time(row.get("window_end")),"recordedAt",time(row.get("recorded_at")),
            "collectionScope",row.get("account_ref")==null?null:facts("accountRef","계정 · …"+((String)row.get("account_ref")).substring(8),"region",row.get("region")),
            "sourceRef",row.get("source_ref_type")==null?null:facts("type",row.get("source_ref_type"),"id",row.get("source_ref_id")),"targetRef",row.get("target_ref_type")==null?null:facts("type",row.get("target_ref_type"),"id",row.get("target_ref_id")),
            "reviewStatus",review,"observationRevision",decisionRevision(id),"allowedDecisions",allowedDecisions(actor,c,row),"currentApplicable",observationCurrent(c,row),
            "decisionHistory",decisions.stream().map(d->facts("decision",d.get("decision"),"reasonCode",d.get("reason_code"),"decidedAt",time(d.get("created_at")),"revision",d.get("observation_revision"))).toList());
    }
    private boolean observationCurrent(Map<String,Object> c,Map<String,Object> row){return number(c,"credential_revision")==number(row,"credential_revision")&&number(c,"scope_revision")==number(row,"scope_revision")&&SecretUsageContext.sourceVersion(c).equals(row.get("source_context_version"))&&"ACTIVE".equals(c.get("connection_status"))&&Boolean.TRUE.equals(c.get("scope_enabled"));}
    private long decisionRevision(long observation){return jdbc.queryForObject("SELECT COALESCE(max(observation_revision),0) FROM secret_usage_decisions WHERE observation_id=?",Long.class,observation);}
    private List<String> allowedDecisions(SecretPrincipal actor,Map<String,Object> c,Map<String,Object> row){
        if(!"MANUAL".equals(row.get("source_kind"))||!observationCurrent(c,row)||!access.hasConnectionRole(actor,number(c,"connection_id"),SecretRole.SECURITY)
            ||!sourceVisible(actor,c,new Ref((String)row.get("source_ref_type"),number(row,"source_ref_id"))))return List.of();
        var previous=jdbc.queryForList("SELECT decision FROM secret_usage_decisions WHERE observation_id=? ORDER BY observation_revision DESC LIMIT 1",number(row,"observation_id"));
        if(previous.isEmpty())return List.of("ACCEPT","REJECT","WITHDRAW");return "WITHDRAW".equals(previous.getFirst().get("decision"))?List.of():List.of("WITHDRAW");
    }
    private List<Map<String,Object>> sourceRefs(SecretPrincipal actor,Map<String,Object> c){
        var refs=new ArrayList<Map<String,Object>>();
        for(var row:jdbc.queryForList("SELECT q.* FROM(SELECT h.history_id,h.event_type,h.created_at,'INVESTIGATION_HISTORY' AS source_ref_type,h.history_id AS source_ref_id FROM secret_investigation_history h JOIN secret_investigation_tasks t USING(task_id) WHERE t.occurrence_id=? OR(t.target_type='SCOPE' AND t.scope_id=?))q WHERE "+sourceVisibility("q",actor,c)+" ORDER BY q.history_id DESC LIMIT 100",number(c,"occurrence_id"),number(c,"scope_id")))refs.add(facts("type","INVESTIGATION_HISTORY","id",row.get("history_id"),"labelCode",Set.of("EVIDENCE_ADDED","EVIDENCE_ACCEPTED","EVIDENCE_REJECTED").contains(row.get("event_type"))?row.get("event_type"):"INVESTIGATION_RECORD","recordedAt",time(row.get("created_at"))));
        for(var row:jdbc.queryForList("SELECT q.* FROM(SELECT action_id,action_type,recorded_at,'ACTION_RECORD' AS source_ref_type,action_id AS source_ref_id FROM secret_action_records WHERE occurrence_id=?)q WHERE "+sourceVisibility("q",actor,c)+" ORDER BY q.action_id DESC LIMIT 100",number(c,"occurrence_id")))refs.add(facts("type","ACTION_RECORD","id",row.get("action_id"),"labelCode",Set.of("ROTATED","REVOKED","REMOVED_FROM_SOURCE","PERMISSION_REDUCED").contains(row.get("action_type"))?row.get("action_type"):"ACTION_RECORD","recordedAt",time(row.get("recorded_at"))));
        return refs;
    }
    private List<Map<String,Object>> targetRefs(Map<String,Object> c){var refs=new ArrayList<Map<String,Object>>();refs.add(facts("type","APPROVED_SCOPE","id",c.get("scope_id")));if(c.get("asset_id")!=null)refs.add(facts("type","ASSET","id",c.get("asset_id")));return refs;}
    private void sourceRef(SecretPrincipal actor,Map<String,Object> c,Ref ref){if(!sourceVisible(actor,c,ref))throw invalid();}
    private boolean sourceVisible(SecretPrincipal actor,Map<String,Object> c,Ref ref){
        if(ref==null||ref.id()==null||ref.id()<=0||!Set.of("INVESTIGATION_HISTORY","ACTION_RECORD").contains(Objects.toString(ref.type(),"")))return false;
        return Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM(VALUES(?::varchar,?::bigint))q(source_ref_type,source_ref_id) WHERE "+sourceVisibility("q",actor,c)+")",Boolean.class,ref.type(),ref.id()));
    }
    /** Mirrors investigation visibility and current per-location action access. Only authenticated numeric IDs enter this SQL. */
    private String sourceVisibility(String alias,SecretPrincipal actor,Map<String,Object> c){
        if(!Set.of("q","u").contains(alias))throw new IllegalArgumentException("INTERNAL_ALIAS");
        boolean security=access.hasConnectionRole(actor,number(c,"connection_id"),SecretRole.SECURITY);
        boolean operations=access.hasConnectionRole(actor,number(c,"connection_id"),SecretRole.OPERATIONS);
        return """
((%1$s.source_ref_type='INVESTIGATION_HISTORY' AND EXISTS(
 SELECT 1 FROM secret_investigation_history h JOIN secret_investigation_tasks t USING(task_id)
 WHERE h.history_id=%1$s.source_ref_id AND (t.occurrence_id=%2$d OR(t.target_type='SCOPE' AND t.scope_id=%3$d))
 AND (%4$s OR(t.target_type='SCOPE' AND %5$s) OR(t.creation_source='HUMAN_HANDOFF' AND t.requested_by_user_id=%6$d AND t.occurrence_id=%2$d))))
 OR(%1$s.source_ref_type='ACTION_RECORD' AND EXISTS(SELECT 1 FROM secret_action_records a JOIN secret_response_cases rc USING(case_id)
 WHERE a.action_id=%1$s.source_ref_id AND a.occurrence_id=%2$d AND rc.is_current)))
""".formatted(alias,number(c,"occurrence_id"),number(c,"scope_id"),security,operations,actor.userId());
    }
    private void targetRef(Map<String,Object> c,Ref ref){if(ref==null||ref.id()==null||ref.type()==null||!("APPROVED_SCOPE".equals(ref.type())&&ref.id()==number(c,"scope_id")||"ASSET".equals(ref.type())&&c.get("asset_id")!=null&&ref.id()==number(c,"asset_id")))throw invalid();}
    private Map<String,Object> iamMetadata(SecretPrincipal actor,Map<String,Object> c){
        var rows=jdbc.queryForList("""
SELECT m.last_used_at,m.last_used_service,m.last_used_region,m.observed_at,o.connection_id
FROM secret_aws_access_key_observations m JOIN secret_occurrences o ON o.credential_set_id=m.credential_set_id
JOIN secret_run_scopes rs ON rs.run_id=m.run_id AND rs.scope_id=o.scope_id
JOIN secret_connection_scopes s ON s.scope_id=rs.scope_id AND s.revision=rs.scope_revision AND s.enabled
JOIN secret_connections c ON c.connection_id=s.connection_id AND c.status='ACTIVE'
JOIN secret_scan_runs r ON r.run_id=rs.run_id AND r.scope_version=c.scope_version AND r.connection_id=c.connection_id
WHERE m.credential_set_id=? AND s.content_type='IAM_ACCESS_KEY_METADATA' ORDER BY m.observed_at DESC LIMIT 100
""",number(c,"credential_set_id"));
        for(var r:rows)if(access.canReadConnectionFacts(actor,number(r,"connection_id")))return facts("lastUsedAt",time(r.get("last_used_at")),"service",safeService(r.get("last_used_service")),"region",safeRegion(r.get("last_used_region")),"observedAt",time(r.get("observed_at")));return null;
    }
    private String safeService(Object value){String s=Objects.toString(value,"");return s.matches("[a-z0-9-]{1,40}")?s:null;}
    private String safeRegion(Object value){String s=Objects.toString(value,"");return s.matches("[a-z]{2}(-[a-z]+)+-[0-9]")?s:null;}
    private void window(OffsetDateTime start,OffsetDateTime end,OffsetDateTime now){if(start==null||end==null||!end.isAfter(start)||end.isAfter(now)||start.isBefore(now.minusDays(90))||Duration.between(start,end).compareTo(Duration.ofDays(90))>0)throw invalid();}
    private boolean canSubmit(SecretPrincipal actor,Map<String,Object> c){return access.canReadOccurrence(actor,number(c,"occurrence_id"))&&"ACTIVE".equals(c.get("connection_status"))&&Boolean.TRUE.equals(c.get("scope_enabled"));}
    private SecretPrincipal reader(String login,long occurrence){var actor=access.requirePrincipal(login);access.requireOccurrenceRead(actor,occurrence);return actor;}
    private Map<String,Object> current(long occurrence,long credential){try{var c=contexts.occurrence(occurrence);if(number(c,"credential_set_id")!=credential)throw new ApiException(ErrorCode.NOT_FOUND);return c;}catch(IllegalArgumentException missing){throw new ApiException(ErrorCode.NOT_FOUND);}}
    private Map<String,Object> lock(long occurrence,long credential){jdbc.queryForObject("SELECT occurrence_id FROM secret_occurrences WHERE occurrence_id=? FOR UPDATE",Long.class,occurrence);jdbc.queryForObject("SELECT credential_set_id FROM secret_credential_sets WHERE credential_set_id=? FOR SHARE",Long.class,credential);var c=current(occurrence,credential);jdbc.queryForList("SELECT connection_id FROM secret_connections WHERE connection_id=? FOR SHARE",number(c,"connection_id"));jdbc.queryForList("SELECT scope_id FROM secret_connection_scopes WHERE scope_id=? FOR SHARE",number(c,"scope_id"));return current(occurrence,credential);}
    private void lockSubmitter(SecretPrincipal actor,long occurrence){jdbc.queryForList("SELECT grant_id FROM secret_role_grants WHERE user_id=? AND revoked_at IS NULL FOR SHARE",actor.userId());jdbc.queryForList("SELECT membership_id FROM secret_team_memberships WHERE user_id=? AND removed_at IS NULL FOR SHARE",actor.userId());jdbc.queryForList("SELECT case_id FROM secret_case_occurrences WHERE occurrence_id=? FOR SHARE",occurrence);jdbc.queryForList("SELECT case_id FROM secret_response_cases WHERE case_id IN(SELECT case_id FROM secret_case_occurrences WHERE occurrence_id=?) FOR SHARE",occurrence);}
    private Map<String,Object> lockTarget(SecretPrincipal actor,long id){var t=contexts.target(id);access.requireConnectionFactsRead(actor,number(t,"collector_connection_id"));jdbc.queryForList("SELECT target_id FROM secret_usage_targets WHERE target_id=? FOR SHARE",id);jdbc.queryForList("SELECT connection_id FROM secret_connections WHERE connection_id=? FOR SHARE",number(t,"collector_connection_id"));jdbc.queryForList("SELECT scope_id FROM secret_connection_scopes WHERE scope_id=? FOR SHARE",number(t,"collector_scope_id"));jdbc.queryForList("SELECT grant_id FROM secret_role_grants WHERE user_id IN(?,?) AND revoked_at IS NULL FOR SHARE",actor.userId(),number(t,"approved_by_user_id"));return contexts.target(id);}
    private void security(SecretPrincipal actor,Map<String,Object> c){jdbc.queryForList("SELECT grant_id FROM secret_role_grants WHERE user_id=? AND revoked_at IS NULL FOR SHARE",actor.userId());access.requireConnectionRole(actor,number(c,"connection_id"),SecretRole.SECURITY);}
    private void revisions(Map<String,Object> c,Long credential,Long scope){if(credential==null||scope==null||number(c,"credential_revision")!=credential||number(c,"scope_revision")!=scope)throw conflict();}
    private Map<String,Object> observation(long id){var rows=jdbc.queryForList("SELECT * FROM secret_usage_observations WHERE observation_id=?",id);if(rows.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);return rows.getFirst();}
    private Map<String,Object> requestRow(long id){try{return contexts.request(id);}catch(IllegalArgumentException missing){throw new ApiException(ErrorCode.NOT_FOUND);}}
    private List<String> array(Object value){try{if(value instanceof java.sql.Array array)return Arrays.asList((String[])array.getArray());if(value instanceof String[] values)return Arrays.asList(values);return List.of();}catch(java.sql.SQLException e){throw new IllegalStateException("USAGE_REASON_UNAVAILABLE");}}
    private static ApiException conflict(){return new ApiException(ErrorCode.CONFLICT);}
}
