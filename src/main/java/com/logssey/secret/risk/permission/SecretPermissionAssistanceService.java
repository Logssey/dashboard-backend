package com.logssey.secret.risk.permission;

import static com.logssey.secret.permission.core.SecretPermissionContext.*;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.permission.core.SecretPermissionContext;
import com.logssey.secret.risk.*;
import com.logssey.secret.risk.core.*;
import java.time.*;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.json.JsonMapper;

/** Automatic observations are candidates. Only a separate human manual submission enters v2. */
@Service
public class SecretPermissionAssistanceService {
    public record Request(String expectedContextVersion,String idempotencyKey,Long collectorConnectionId){}
    public record Confirm(String expectedContextVersion,Long expectedEvidenceRevision,String idempotencyKey,Boolean attestation,String evidenceRef,OffsetDateTime observedAt,OffsetDateTime validUntil,Map<String,Object> facts,List<SecretRiskProvenance.Ref> sourceRefs,OffsetDateTime applicableFrom,OffsetDateTime applicableUntil,@com.fasterxml.jackson.annotation.JsonInclude(com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL) Boolean savePartial){
        public Confirm(String context,Long revision,String key,Boolean attestation,String ref,OffsetDateTime observed,OffsetDateTime until,Map<String,Object> facts,List<SecretRiskProvenance.Ref> refs,OffsetDateTime from,OffsetDateTime to){this(context,revision,key,attestation,ref,observed,until,facts,refs,from,to,null);}
        public Confirm(String context,Long revision,String key,Boolean attestation,String ref,OffsetDateTime observed,OffsetDateTime until,Map<String,Object> facts,List<SecretRiskProvenance.Ref> refs){this(context,revision,key,attestation,ref,observed,until,facts,refs,null,null,null);}
    }
    public record Reject(String expectedContextVersion,String idempotencyKey,String reasonCode){}
    private static final Set<String> TYPES=Set.of("AWS_ACCESS_KEY_PAIR","AWS_TEMPORARY_CREDENTIALS","GITHUB_CLASSIC_PAT","GITHUB_FINE_GRAINED_PAT");
    private final JdbcTemplate jdbc;private final SecretAccessService access;private final SecretRiskCommands commands;private final SecretRiskEvidenceService evidence;
    private final boolean enabled;private final JsonMapper json=JsonMapper.builder().findAndAddModules().build();private final SecretPermissionContext contexts;
    public SecretPermissionAssistanceService(JdbcTemplate jdbc,SecretAccessService access,SecretRiskCommands commands,SecretRiskEvidenceService evidence,@Value("${logssey.secret.permissions.enabled:false}")boolean enabled){this.jdbc=jdbc;this.access=access;this.commands=commands;this.evidence=evidence;this.enabled=enabled;this.contexts=new SecretPermissionContext(jdbc);}

    @Transactional(readOnly=true)
    public Map<String,Object> context(String login,long occurrence){
        var actor=reader(login,occurrence);var c=current(occurrence);var blocked=blocked(actor,c);
        var options=collectors(actor,c);
        // The principal/account is needed to match an approved collector. Before validation,
        // an empty option list means "not yet determined", not "no approved connection".
        if(c.get("identity_id")!=null&&options.isEmpty())blocked.add("APPROVED_COLLECTOR_REQUIRED");
        var latest=jdbc.queryForList("SELECT request_id FROM secret_permission_requests WHERE occurrence_id=? ORDER BY request_id DESC LIMIT 1",occurrence);
        var request=latest.isEmpty()?null:status(login,occurrence,number(latest.getFirst(),"request_id"));
        return facts("occurrenceId",occurrence,"contextVersion",version(c),"evidenceRevision",c.get("risk_evidence_revision"),
            "support",facts("status",supported(c)?"PARTIAL":"UNSUPPORTED","reasonCodes",supported(c)?List.of("AUTOMATIC_IMPACT_UNSUPPORTED","HUMAN_CONFIRMATION_REQUIRED"):List.of("GITHUB".equals(c.get("issuer"))?"CROSS_SOURCE_PERMISSION_UNSUPPORTED":"UNSUPPORTED_TYPE")),
            "identity",facts("status",c.get("identity_id")==null?"UNAVAILABLE":"MATCHED","provider",c.get("issuer"),"principalType",c.get("principal_type"),"observedAt",time(c.get("identity_observed_at")),"validationAttemptId",c.get("validation_attempt_id")),
            "supplementation",supplementation(actor,c),
            "requestReadiness",SecretPermissionReadiness.describe(blocked,c.get("identity_id")!=null,!options.isEmpty()),
            "collectorOptions",options.stream().map(o->facts("connectionId",o.get("connection_id"),"displayName",com.logssey.secret.connection.SecretDisplayLabels.safeAlias((String)o.get("display_name"))?o.get("display_name"):"연결 #"+o.get("connection_id"))).toList(),
            "latestRequest",request,"latestObservation",request==null?null:request.get("observation"),"capabilities",facts("canRequest",blocked.isEmpty(),"blockedReasonCodes",blocked));
    }

    public Map<String,Object> request(String login,long occurrence,Request body){
        if(body==null||body.expectedContextVersion()==null)throw invalid();var actor=reader(login,occurrence);
        return commands.execute(actor,"PERMISSION_ASSISTANCE_REQUESTED",body.idempotencyKey(),facts("occurrenceId",occurrence,"expected",body.expectedContextVersion(),"collector",body.collectorConnectionId()),
            ()->security(actor,current(occurrence)),()->{
                var c=lock(occurrence);same(body.expectedContextVersion(),c);var reasons=blocked(actor,c);if(!reasons.isEmpty())throw new ApiException(ErrorCode.UNPROCESSABLE);
                var choices=collectors(actor,c);Map<String,Object> chosen;
                if(body.collectorConnectionId()==null){if(choices.size()!=1)throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);chosen=choices.getFirst();}
                else chosen=choices.stream().filter(v->number(v,"connection_id")==body.collectorConnectionId()).findFirst().orElseThrow(()->new ApiException(ErrorCode.FORBIDDEN));
                lockCollector(actor,number(chosen,"connection_id"));
                if(!jdbc.queryForList("SELECT job_id FROM secret_jobs WHERE kind='ENRICH' AND target_occurrence_id=? AND status IN('PENDING','LEASED')",occurrence).isEmpty())throw new ApiException(ErrorCode.CONFLICT);
                long recent=jdbc.queryForObject("SELECT count(*) FROM secret_permission_requests WHERE requested_by_user_id=? AND requested_at>clock_timestamp()-interval '1 minute'",Long.class,actor.userId());if(recent>=10)throw new ApiException(ErrorCode.UNPROCESSABLE);
                var baseline=new TreeMap<String,Object>();baseline.put("contextVersion",version(c));baseline.put("sourceContextVersion",sourceVersion(c));baseline.put("collectorScopeVersion",chosen.get("scope_version"));baseline.put("collectorAuthRef",chosen.get("auth_ref"));baseline.put("collectorScopeId",chosen.get("scope_id"));baseline.put("collectorScopeRevision",chosen.get("revision"));baseline.put("collectorApprovedRef",chosen.get("approved_ref"));
                long job=jdbc.queryForObject("""
INSERT INTO secret_jobs(kind,purpose,connection_id,target_occurrence_id,requested_by_user_id,idempotency_key,expected_context,expected_evidence_revision,scheduled_at,available_at,attempt_no,max_attempts,status)
VALUES('ENRICH','PERMISSION_ASSISTANCE',?,?,?, ?,?::jsonb,?,clock_timestamp(),clock_timestamp(),0,3,'PENDING') RETURNING job_id
""",Long.class,number(c,"connection_id"),occurrence,actor.userId(),"permission:"+UUID.randomUUID(),json.writeValueAsString(baseline),number(c,"risk_evidence_revision"));
                long id=jdbc.queryForObject("INSERT INTO secret_permission_requests(job_id,occurrence_id,identity_id,collector_connection_id,requested_by_user_id,context_version,baseline) VALUES(?,?,?,?,?,?,?::jsonb) RETURNING request_id",Long.class,job,occurrence,number(c,"identity_id"),number(chosen,"connection_id"),actor.userId(),version(c),json.writeValueAsString(baseline));
                var result=status(login,occurrence,id);result.put("evidenceRevision",c.get("risk_evidence_revision"));return result;
            });
    }

    @Transactional(readOnly=true)
    public Map<String,Object> status(String login,long occurrence,long request){
        reader(login,occurrence);var c=current(occurrence);
        var rows=jdbc.queryForList("SELECT r.request_id,r.requested_at,j.job_id,j.status,j.last_error_code,j.finished_at FROM secret_permission_requests r JOIN secret_jobs j USING(job_id) WHERE r.request_id=? AND r.occurrence_id=?",request,occurrence);
        if(rows.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);var r=rows.getFirst();var observations=jdbc.queryForList("SELECT * FROM secret_permission_observations WHERE request_id=?",request);
        return facts("occurrenceId",occurrence,"requestId",request,"jobId",r.get("job_id"),"status",r.get("status"),"failureCode",r.get("last_error_code"),"requestedAt",time(r.get("requested_at")),"finishedAt",time(r.get("finished_at")),"currentContextVersion",version(c),"observation",observations.isEmpty()?null:publicObservation(observations.getFirst()));
    }

    @Transactional(readOnly=true)
    public Map<String,Object> preview(String login,long occurrence,long observation){
        var actor=reader(login,occurrence);var c=current(occurrence);var o=observation(occurrence,observation);var result=publicObservation(o);var reasons=confirmBlocked(actor,c,o);
        result.put("contextVersion",version(c));result.put("evidenceRevision",c.get("risk_evidence_revision"));result.put("availableSourceRefs",new SecretRiskProvenance(jdbc).available(c));result.put("canConfirm",reasons.isEmpty());result.put("blockedReasonCodes",reasons);
        result.put("supplementation",supplementation(actor,c));
        result.put("canSavePartial",partialBlocked(actor,c,o).isEmpty());
        result.put("partialBlockedReasonCodes",partialBlocked(actor,c,o));
        result.put("partialDefaults",facts("observedAt",time(o.get("observed_at")),"validUntil",time(o.get("expires_at"))));
        result.put("sourcePresenceObservedAt",time(c.get("last_seen_at")));
        result.put("latestDraft",latestDraft(c,o));
        result.put("canReject",access.hasConnectionRole(actor,number(c,"connection_id"),SecretRole.SECURITY)&&jdbc.queryForList("SELECT decision_id FROM secret_permission_decisions WHERE observation_id=? AND decision IN('CONFIRMED','REJECTED')",observation).isEmpty());
        return result;
    }

    public Map<String,Object> confirm(String login,long occurrence,long observation,Confirm body){
        if(body==null||!Boolean.TRUE.equals(body.attestation())||body.expectedEvidenceRevision()==null||body.facts()==null)throw invalid();var actor=reader(login,occurrence);
        return commands.execute(actor,"PERMISSION_ASSISTANCE_CONFIRMED",body.idempotencyKey(),facts("occurrenceId",occurrence,"observationId",observation,"body",body),()->{security(actor,current(occurrence));lockCollector(actor,number(observation(occurrence,observation),"collector_connection_id"));},()->{
            var c=lock(occurrence);same(body.expectedContextVersion(),c);if(number(c,"risk_evidence_revision")!=body.expectedEvidenceRevision())throw new ApiException(ErrorCode.CONFLICT);
            var observed=observation(occurrence,observation);lockCollector(actor,number(observed,"collector_connection_id"));jdbc.queryForList("SELECT scope_id FROM secret_connection_scopes WHERE connection_id=? FOR SHARE",number(observed,"collector_connection_id"));var blocked=Boolean.TRUE.equals(body.savePartial())?partialBlocked(actor,c,observed):confirmBlocked(actor,c,observed);if(!blocked.isEmpty())throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
            var payload=payload(observed);var proposed=SecretRiskFacts.validate("PERMISSION_MAPPING","OCCURRENCE",body.facts());
            if(Boolean.TRUE.equals(body.savePartial()))return savePartial(login,actor,occurrence,observation,c,observed,body,proposed);
            if(!(payload.get("capabilities") instanceof List<?> capabilities)||!capabilities.contains(proposed.get("capability")))throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
            for(String field:List.of("permissionCoverage","targetCoverage","restrictionCoverage","classificationCoverage"))if(!"COMPLETE".equals(proposed.get(field)))throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
            if(body.observedAt()==null||body.observedAt().isBefore(time(observed.get("observed_at")))||body.validUntil()==null||body.validUntil().isAfter(time(observed.get("expires_at"))))throw invalid();
            // Actual accepted investigation + classification + validation parents are mandatory.
            // Candidate coverage and a checkbox are never a substitute for these independent facts.
            var refs=body.sourceRefs()==null?List.<SecretRiskProvenance.Ref>of():body.sourceRefs();
            if(!new SecretRiskProvenance(jdbc).permissionGrounded(c,refs)||refs.stream().noneMatch(ref->"VALIDATION_ATTEMPT".equals(ref.type())&&ref.id()==number(c,"validation_attempt_id")))throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
            var submitted=evidence.submit(login,occurrence,new SecretRiskEvidenceService.Submission(body.expectedEvidenceRevision(),"permission-confirm:"+digest(body.idempotencyKey()),"PERMISSION_MAPPING","OCCURRENCE",body.observedAt(),body.validUntil(),body.evidenceRef(),proposed,refs,null,body.applicableFrom(),body.applicableUntil()));
            jdbc.update("INSERT INTO secret_permission_decisions(observation_id,actor_user_id,decision,evidence_id,reason_code,context_version) VALUES(?,?,'CONFIRMED',?,'HUMAN_PERMISSION_ATTESTATION',?)",observation,actor.userId(),submitted.get("evidenceId"),body.expectedContextVersion());
            var result=new LinkedHashMap<String,Object>(submitted);result.put("status","CONFIRMED");result.put("observationId",observation);return result;
        });
    }

    private Map<String,Object> savePartial(String login,SecretPrincipal actor,long occurrence,long observation,
            Map<String,Object> context,Map<String,Object> observed,Confirm body,Map<String,Object> proposed) {
        var capabilities=payload(observed).get("capabilities");
        if(!"UNKNOWN".equals(proposed.get("capability"))
                && (!(capabilities instanceof List<?> available) || !available.contains(proposed.get("capability"))))
            throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
        OffsetDateTime observedAt=body.observedAt()==null?time(observed.get("observed_at")):body.observedAt();
        OffsetDateTime until=body.validUntil()==null?time(observed.get("expires_at")):body.validUntil();
        if(observedAt.isBefore(time(observed.get("observed_at"))) || until.isAfter(time(observed.get("expires_at"))))throw invalid();
        String reference=body.evidenceRef()==null || body.evidenceRef().isBlank()
                ? "CHANGE:PERMISSION-"+observation : body.evidenceRef();
        var refs=body.sourceRefs()==null?List.<SecretRiskProvenance.Ref>of():body.sourceRefs();
        var saved=evidence.submitDraft(login,occurrence,new SecretRiskEvidenceService.Submission(
                body.expectedEvidenceRevision(),"permission-draft:"+digest(body.idempotencyKey()),"PERMISSION_MAPPING","OCCURRENCE",
                observedAt,until,reference,proposed,refs,null,body.applicableFrom(),body.applicableUntil()));
        jdbc.update("INSERT INTO secret_permission_decisions(observation_id,actor_user_id,decision,evidence_id,reason_code,context_version) "
                + "VALUES(?,?,'DRAFTED',?,'PARTIAL_PERMISSION_RECORDED',?)",observation,actor.userId(),saved.get("evidenceId"),body.expectedContextVersion());
        var result=new LinkedHashMap<String,Object>(saved);
        result.put("status","SAVED_PARTIAL");result.put("observationId",observation);
        result.put("evidenceRef",reference);result.put("referenceSource",body.evidenceRef()==null || body.evidenceRef().isBlank()?"INTERNAL":"PROVIDED");
        return result;
    }

    @SuppressWarnings("unchecked")
    private Map<String,Object> latestDraft(Map<String,Object> context,Map<String,Object> observed) {
        var rows=jdbc.queryForList("""
            SELECT e.*,(SELECT (command.safe_result->>'evidenceRevision')::bigint
              FROM secret_command_idempotency command
              WHERE command.command_kind='RISK_EVIDENCE_SUBMITTED'
                AND command.safe_result->>'evidenceId'=e.evidence_id::text ORDER BY command.command_id DESC LIMIT 1) AS saved_revision
            FROM secret_permission_decisions d JOIN secret_risk_evidence e USING(evidence_id)
            WHERE d.observation_id=? AND d.decision='DRAFTED' AND e.occurrence_id=?
            ORDER BY d.decision_id DESC LIMIT 1
            """,observed.get("observation_id"),context.get("occurrence_id"));
        if(rows.isEmpty())return null;
        var row=rows.getFirst();var baseline=json.readValue(observed.get("baseline").toString(),Map.class);
        String reason="CURRENT_DRAFT";
        if(!jdbc.queryForList("SELECT decision_id FROM secret_permission_decisions WHERE observation_id=? AND decision IN('CONFIRMED','REJECTED')",observed.get("observation_id")).isEmpty())reason="DRAFT_REVIEWED";
        else if(!Objects.equals(baseline.get("sourceContextVersion"),sourceVersion(context)))reason="DRAFT_CONTEXT_CHANGED";
        else if(!Objects.equals(row.get("saved_revision"),context.get("risk_evidence_revision")))reason="EVIDENCE_REVISION_CHANGED";
        else if(!time(row.get("expires_at")).isAfter(OffsetDateTime.now(ZoneOffset.UTC)))reason="DRAFT_EXPIRED";
        var available=new SecretRiskProvenance(jdbc).available(context);
        var refs=(List<Map<String,Object>>)json.readValue(row.get("source_refs").toString(),List.class);
        var visibleRefs=refs.stream().filter(ref->available.stream().anyMatch(candidate->
            List.of("type","id","version","role").stream().allMatch(key->Objects.toString(ref.get(key),"")
                .equals(Objects.toString(candidate.get(key),""))))).toList();
        return facts("evidenceId",row.get("evidence_id"),"evidenceRevision",row.get("saved_revision"),
            "observationId",observed.get("observation_id"),"savedAt",time(row.get("recorded_at")),
            "observedAt",time(row.get("observed_at")),"validUntil",time(row.get("expires_at")),
            "evidenceRef",row.get("evidence_ref"),"facts",json.readValue(row.get("safe_payload").toString(),Map.class),
            "sourceRefs",visibleRefs,"applicableFrom",time(row.get("fact_valid_from")),
            "applicableUntil",time(row.get("fact_valid_until")),"canRestore",reason.equals("CURRENT_DRAFT"),"reasonCode",reason);
    }

    private List<String> partialBlocked(SecretPrincipal actor,Map<String,Object> context,Map<String,Object> observation) {
        return confirmBlocked(actor,context,observation).stream().filter(reason -> !Set.of(
                "NO_SUPPORTED_CAPABILITY","ASSET_CLASSIFICATION_REQUIRED","PERMISSION_ASSERTION_REQUIRED",
                "RESTRICTION_PROOF_REQUIRED").contains(reason)).toList();
    }

    public Map<String,Object> reject(String login,long occurrence,long observation,Reject body){
        if(body==null||body.reasonCode()==null||!Set.of("NOT_APPLICABLE","INSUFFICIENT_EVIDENCE","IDENTITY_MISMATCH").contains(body.reasonCode()))throw invalid();var actor=reader(login,occurrence);
        return commands.execute(actor,"PERMISSION_ASSISTANCE_REJECTED",body.idempotencyKey(),facts("occurrenceId",occurrence,"observation",observation,"body",body),()->security(actor,current(occurrence)),()->{
            var c=lock(occurrence);same(body.expectedContextVersion(),c);observation(occurrence,observation);if(!jdbc.queryForList("SELECT decision_id FROM secret_permission_decisions WHERE observation_id=? AND decision IN('CONFIRMED','REJECTED')",observation).isEmpty())throw new ApiException(ErrorCode.CONFLICT);
            jdbc.update("INSERT INTO secret_permission_decisions(observation_id,actor_user_id,decision,reason_code,context_version) VALUES(?,?,'REJECTED',?,?)",observation,actor.userId(),body.reasonCode(),body.expectedContextVersion());
            return facts("occurrenceId",occurrence,"observationId",observation,"status","REJECTED","evidenceRevision",c.get("risk_evidence_revision"));
        });
    }

    private SecretPrincipal reader(String login,long occurrence){var actor=access.requirePrincipal(login);access.requireOccurrenceRead(actor,occurrence);return actor;}
    private Map<String,Object> current(long occurrence){try{return contexts.read(occurrence);}catch(IllegalArgumentException missing){throw new ApiException(ErrorCode.NOT_FOUND);}}
    private Map<String,Object> lock(long occurrence){jdbc.queryForObject("SELECT occurrence_id FROM secret_occurrences WHERE occurrence_id=? FOR UPDATE",Long.class,occurrence);return current(occurrence);}
    private void same(String expected,Map<String,Object> c){if(expected==null||!expected.equals(version(c)))throw new ApiException(ErrorCode.CONFLICT);}
    private void security(SecretPrincipal actor,Map<String,Object> c){jdbc.queryForList("SELECT grant_id FROM secret_role_grants WHERE user_id=? AND role='SECURITY' AND revoked_at IS NULL AND(connection_id IS NULL OR connection_id=?) FOR SHARE",actor.userId(),number(c,"connection_id"));access.requireConnectionRole(actor,number(c,"connection_id"),SecretRole.SECURITY);}
    private void lockCollector(SecretPrincipal actor,long id){jdbc.queryForObject("SELECT connection_id FROM secret_connections WHERE connection_id=? FOR SHARE",Long.class,id);jdbc.queryForList("SELECT grant_id FROM secret_role_grants WHERE user_id=? AND role IN('SECURITY','OPERATIONS') AND revoked_at IS NULL AND(connection_id IS NULL OR connection_id=?) FOR SHARE",actor.userId(),id);access.requireConnectionFactsRead(actor,id);}
    private static boolean supported(Map<String,Object> c){return TYPES.contains(c.get("credential_type"))&&(!"GITHUB".equals(c.get("issuer"))||"GITHUB".equals(c.get("source_provider")));}
    private List<String> blocked(SecretPrincipal actor,Map<String,Object> c){var result=new ArrayList<String>();if(!enabled)result.add("WORKER_NOT_CONFIGURED");if(!access.hasConnectionRole(actor,number(c,"connection_id"),SecretRole.SECURITY))result.add("SECURITY_REQUIRED");if(!TYPES.contains(c.get("credential_type")))result.add("UNSUPPORTED_TYPE");else if(!supported(c))result.add("CROSS_SOURCE_PERMISSION_UNSUPPORTED");if(!"CONFIRMED".equals(c.get("component_state")))result.add("COMPLETE_IDENTITY_REQUIRED");if(c.get("identity_id")==null)result.add("FRESH_IDENTITY_VALIDATION_REQUIRED");if(!"ACTIVE".equals(c.get("connection_status"))||!Boolean.TRUE.equals(c.get("scope_enabled")))result.add("SOURCE_UNAVAILABLE");return result;}
    private List<Map<String,Object>> collectors(SecretPrincipal actor,Map<String,Object> c){
        if(c.get("identity_id")==null)return List.of();
        String condition="AWS".equals(c.get("issuer"))?"c.provider='AWS' AND s.content_type='IAM_ACCESS_KEY_METADATA' AND s.approved_ref=? AND (s.history_limit IS NULL OR s.history_limit='CURRENT_STATE_ONLY')":"c.connection_id=? AND c.provider='GITHUB' AND s.scope_id=?";
        var args=new ArrayList<Object>();if("AWS".equals(c.get("issuer")))args.add("aws://"+c.get("account_ref")+"/global/iam/access-keys");else {args.add(number(c,"connection_id"));args.add(number(c,"scope_id"));}
        return jdbc.queryForList("SELECT DISTINCT ON(c.connection_id) c.connection_id,c.display_name,c.auth_ref,c.scope_version,s.scope_id,s.revision,s.approved_ref FROM secret_connections c JOIN secret_connection_scopes s USING(connection_id) WHERE c.status='ACTIVE' AND s.enabled AND "+condition+" ORDER BY c.connection_id,s.scope_id",args.toArray()).stream().filter(r->access.canReadConnectionFacts(actor,number(r,"connection_id"))).toList();
    }
    private Map<String,Object> observation(long occurrence,long id){var rows=jdbc.queryForList("SELECT o.*,r.context_version,r.collector_connection_id,r.identity_id,r.baseline::text AS baseline FROM secret_permission_observations o JOIN secret_permission_requests r USING(request_id) WHERE o.observation_id=? AND r.occurrence_id=?",id,occurrence);if(rows.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);return rows.getFirst();}
    @SuppressWarnings("unchecked")private Map<String,Object> payload(Map<String,Object> observation){return json.readValue(observation.get("safe_facts").toString(),Map.class);}
    private Map<String,Object> publicObservation(Map<String,Object> o){var result=new LinkedHashMap<String,Object>(payload(o));result.put("observationId",o.get("observation_id"));result.put("status",o.get("status"));result.put("observerVersion",o.get("observer_version"));result.put("observedAt",time(o.get("observed_at")));result.put("recordedAt",time(o.get("created_at")));result.put("expiresAt",time(o.get("expires_at")));var decisions=jdbc.queryForList("SELECT decision FROM secret_permission_decisions WHERE observation_id=? ORDER BY decision_id DESC",o.get("observation_id"));result.put("decision",decisions.isEmpty()?null:decisions.getFirst().get("decision"));return result;}
    private List<String> confirmBlocked(SecretPrincipal actor,Map<String,Object> c,Map<String,Object> o){var reasons=blocked(actor,c);var baseline=json.readValue(o.get("baseline").toString(),Map.class);if(!Objects.equals(baseline.get("sourceContextVersion"),sourceVersion(c)))reasons.add("CONTEXT_CHANGED");if(!time(o.get("expires_at")).isAfter(OffsetDateTime.now(ZoneOffset.UTC)))reasons.add("OBSERVATION_EXPIRED");if("UNSUPPORTED".equals(o.get("status")))reasons.add("UNSUPPORTED_TYPE");if(!(payload(o).get("capabilities") instanceof List<?> caps)||caps.isEmpty())reasons.add("NO_SUPPORTED_CAPABILITY");if(!jdbc.queryForList("SELECT decision_id FROM secret_permission_decisions WHERE observation_id=? AND decision IN('CONFIRMED','REJECTED')",o.get("observation_id")).isEmpty())reasons.add("ALREADY_REVIEWED");if(!access.canReadConnectionFacts(actor,number(o,"collector_connection_id")))reasons.add("COLLECTOR_NOT_AUTHORIZED");
        boolean collectorCurrent=collectors(actor,c).stream().filter(row->number(row,"connection_id")==number(o,"collector_connection_id")).anyMatch(row->Objects.toString(row.get("auth_ref"),"").equals(Objects.toString(baseline.get("collectorAuthRef"),""))&&Objects.toString(row.get("scope_version"),"").equals(Objects.toString(baseline.get("collectorScopeVersion"),""))&&Objects.toString(row.get("scope_id"),"").equals(Objects.toString(baseline.get("collectorScopeId"),""))&&Objects.toString(row.get("revision"),"").equals(Objects.toString(baseline.get("collectorScopeRevision"),""))&&Objects.equals(row.get("approved_ref"),baseline.get("collectorApprovedRef")));
        if(!collectorCurrent)reasons.add("COLLECTOR_APPROVAL_CHANGED");
        var refs=new SecretRiskProvenance(jdbc).available(c);
        if(refs.stream().noneMatch(r->"VALIDATION_ATTEMPT".equals(r.get("type"))&&Objects.equals(((Number)r.get("id")).longValue(),c.get("validation_attempt_id"))))reasons.add("IDENTITY_PROOF_REQUIRED");
        if(refs.stream().noneMatch(r->"RISK_EVIDENCE".equals(r.get("type"))))reasons.add("ASSET_CLASSIFICATION_REQUIRED");
        if(refs.stream().noneMatch(r->"INVESTIGATION_HISTORY".equals(r.get("type"))&&"ASSERTS".equals(r.get("role"))))reasons.add("PERMISSION_ASSERTION_REQUIRED");
        if(refs.stream().noneMatch(r->"INVESTIGATION_HISTORY".equals(r.get("type"))&&"LIMITS".equals(r.get("role"))))reasons.add("RESTRICTION_PROOF_REQUIRED");
        return reasons;}
    private Map<String,Object> supplementation(SecretPrincipal actor,Map<String,Object> c){var tasks=jdbc.queryForList("SELECT task_id FROM secret_investigation_tasks WHERE target_type='OCCURRENCE' AND occurrence_id=? AND status='OPEN' ORDER BY task_id DESC LIMIT 1",number(c,"occurrence_id"));return facts("investigationTaskId",tasks.isEmpty()?null:tasks.getFirst().get("task_id"),"occurrenceVersion",c.get("exposure_assessment_version"),"canRequestInvestigation",access.hasConnectionRole(actor,number(c,"connection_id"),SecretRole.SECURITY));}
    private static ApiException invalid(){return new ApiException(ErrorCode.INVALID_INPUT);}
}
