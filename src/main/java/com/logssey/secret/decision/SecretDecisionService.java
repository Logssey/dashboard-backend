package com.logssey.secret.decision;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.time.OffsetDateTime;
import java.util.*;
import java.util.function.Supplier;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.evidence.SecretEvidenceRules;
import com.logssey.secret.investigation.SecretInvestigationService;
import com.logssey.secret.query.*;
import com.logssey.secret.snapshot.SecretReadSnapshots;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.ObjectMapper;
import static com.logssey.secret.decision.SecretDecisionContracts.*;
import static com.logssey.secret.evidence.SecretEvidenceRules.*;

@Service
public class SecretDecisionService {
    private final JdbcTemplate jdbc;
    private final SecretAccessService access;
    private final SecretReadSnapshots snapshots;
    private final SecretInvestigationService investigations;
    private final SecretLocationRepository locations;
    private final ObjectMapper json;
    private final TransactionTemplate tx;
    private static final Set<String> DECISIONS=Set.of("NORMAL","ABNORMAL","FALSE_POSITIVE","NEEDS_MORE_INFO");
    private static final Set<String> SAFE_VALIDITY_REASONS=Set.of("AUTHENTICATED","INVALID_ACCESS_KEY","SIGNATURE_AMBIGUOUS",
        "EXPIRED_SESSION","DISABLED","INCOMPLETE_PAIR","MISSING_SESSION_TOKEN","ACCESS_AMBIGUOUS","RATE_LIMITED",
        "PROVIDER_UNAVAILABLE","CLIENT_FAILURE","SYNTHETIC_FIXTURE","SOURCE_UNAVAILABLE");

    public SecretDecisionService(JdbcTemplate jdbc,SecretAccessService access,SecretReadSnapshots snapshots,
        SecretInvestigationService investigations,SecretLocationRepository locations,ObjectMapper json,
        PlatformTransactionManager manager) {
        this.jdbc=jdbc;this.access=access;this.snapshots=snapshots;this.investigations=investigations;
        this.locations=locations;this.json=json;this.tx=new TransactionTemplate(manager);
    }

    @Transactional(readOnly=true,isolation=Isolation.REPEATABLE_READ)
    public ReviewContext context(String login,long id) {
        var actor=access.requirePrincipal(login);access.requireOccurrenceRead(actor,id);
        return project(actor,read(id));
    }

    public DecisionResult decide(String login,long id,DecisionRequest request) {
        if(request==null)invalid();
        code(request.decision(),DECISIONS);
        var evidence=normalizeEvidence(request.evidenceRefs());
        expected(request.expectedOccurrenceVersion());expected(request.expectedScopeVersion());
        if(request.expectedPolicyVersion()!=null)expected(request.expectedPolicyVersion());
        if("NEEDS_MORE_INFO".equals(request.decision())) {
            code(request.missingReasonCode(),MISSING_REASONS);reference(request.evidenceRef(),true);
            future(request.dueAt(),true);if(request.followUpOwnerUserId()==null)invalid();
        } else if(request.missingReasonCode()!=null||request.followUpOwnerUserId()!=null||request.dueAt()!=null||request.evidenceRef()!=null)invalid();
        var actor=access.requirePrincipal(login);
        return execute(actor,id,"TRIAGE_DECISION",request.idempotencyKey(),digest(id,request.decision(),request.reasonCode(),
            request.findingId(),evidence,request.expectedOccurrenceVersion(),request.expectedScopeVersion(),request.expectedPolicyVersion(),
            request.missingReasonCode(),request.followUpOwnerUserId(),request.dueAt(),request.evidenceRef()),()->{
            var row=lock(actor,id);
            checkVersions(row,request.expectedOccurrenceVersion(),request.expectedScopeVersion(),request.expectedPolicyVersion());
            var allowed=allowedReasons(actor,row);
            if(!"NEEDS_MORE_INFO".equals(request.decision())&&!currentValue(row))throw new SecretReviewConflict("presence");
            if("NORMAL".equals(request.decision())&&!"ALLOWED".equals(row.get("policy_result")))throw new SecretReviewConflict("policy");
            if("POLICY_PROHIBITED_LOCATION".equals(request.reasonCode())&&!"DENIED".equals(row.get("policy_result")))throw new SecretReviewConflict("policy");
            if(!allowed.getOrDefault(request.decision(),List.of()).contains(request.reasonCode()))
                throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
            Map<String,Object> finding=null;
            if(request.findingId()!=null)finding=currentFinding(id,request.findingId());
            if(!"NEEDS_MORE_INFO".equals(request.decision())&&finding==null)throw new SecretReviewConflict("finding");
            if(evidence.isEmpty()&&!"NEEDS_MORE_INFO".equals(request.decision()))throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
            long version=number(row,"exposure_assessment_version")+1;
            long decision=recordDecision(actor,row,finding,request.decision(),request.reasonCode(),evidence,version);
            String exposure=Set.of("NORMAL","ABNORMAL").contains(request.decision())?request.decision():text(row,"exposure_status");
            // FP changes Finding truth only. It never asserts a NORMAL location or INVALID credential.
            if(Set.of("NORMAL","ABNORMAL").contains(request.decision()))jdbc.update("""
                    UPDATE secret_occurrences SET exposure_status=?,exposure_assessment_version=?,
                      policy_assessed_binding_id=?,policy_assessed_origin_version=?,policy_recheck_required=false
                    WHERE occurrence_id=?
                    """,exposure,version,row.get("binding_id"),row.get("response_origin_version"),id);
            else jdbc.update("UPDATE secret_occurrences SET exposure_assessment_version=? WHERE occurrence_id=?",version,id);
            Long correction=null,task=null;
            if("FALSE_POSITIVE".equals(request.decision()))correction=correct(actor,row,finding,decision,request.reasonCode());
            if("NEEDS_MORE_INFO".equals(request.decision()))task=investigations.createHumanTaskTx(actor,id,
                request.missingReasonCode(),request.followUpOwnerUserId(),request.dueAt(),request.evidenceRef());
            var linked="ABNORMAL".equals(request.decision())?attach(actor,row,decision,false):
                new Link(nullableNumber(row,"case_id"),"NONE",nullableNumber(row,"case_version"));
            snapshots.invalidateOccurrence(id);
            // Corrections also update the existing TEST warning, never silently dismiss it.
            if(correction!=null)jdbc.query("SELECT secret_reconcile_test_alerts(NULL::bigint)",(rs,n)->rs.getObject(1));
            String bucket=bucket(read(id));
            return new DecisionResult(decision,id,exposure,linked.caseId(),linked.operation(),linked.version(),task,correction,bucket,true);
        });
    }

    public DecisionResult link(String login,long id,LinkRequest request) {
        if(request==null||request.decisionId()==null||request.decisionId()<=0)invalid();
        expected(request.expectedDecisionVersion());expected(request.expectedOccurrenceVersion());expected(request.expectedScopeVersion());
        var actor=access.requirePrincipal(login);
        return execute(actor,id,"CASE_LINK",request.idempotencyKey(),digest(id,request.decisionId(),request.expectedDecisionVersion(),
            request.expectedOccurrenceVersion(),request.expectedScopeVersion()),()->{
            var row=lock(actor,id);
            if(row.get("case_id")!=null)throw new SecretReviewConflict("caseVersion");
            checkVersions(row,request.expectedOccurrenceVersion(),request.expectedScopeVersion(),nullableNumber(row,"policy_version"));
            var decisions=jdbc.queryForList("""
                SELECT assessment_id,version,decision FROM secret_exposure_assessments
                WHERE assessment_id=? AND occurrence_id=? AND version=? AND decision='ABNORMAL'
                  AND scope_origin=? AND scope_version=? AND scope_revision=?
                  AND policy_binding_id IS NOT DISTINCT FROM ?::bigint
                  AND policy_version IS NOT DISTINCT FROM ?::bigint
                """,request.decisionId(),id,request.expectedDecisionVersion(),row.get("response_origin"),
                row.get("response_origin_version"),row.get("revision"),row.get("binding_id"),row.get("policy_version"));
            if(decisions.isEmpty()||number(row,"exposure_assessment_version")!=request.expectedDecisionVersion()
                ||!"ABNORMAL".equals(row.get("exposure_status"))||!currentValue(row)||validFindings(id)==0
                ||Boolean.TRUE.equals(row.get("requires_reassessment")))throw new SecretReviewConflict("decision","finding","policy");
            var linked=attach(actor,row,request.decisionId(),true);
            snapshots.invalidateOccurrence(id);
            return new DecisionResult(request.decisionId(),id,"ABNORMAL",linked.caseId(),linked.operation(),linked.version(),
                null,null,"ACTION_REQUIRED",true);
        });
    }

    @Transactional(readOnly=true,isolation=Isolation.REPEATABLE_READ)
    public QueuePage queue(String login,String bucket,String origin,int page,int size) {
        page(page,size);code(bucket,Set.of("ACTION_REQUIRED","NEEDS_DECISION","NORMAL_INVENTORY","NEEDS_CASE_LINK"));
        code(origin,Set.of("PRODUCTION","TEST","UNCLASSIFIED"));
        var actor=access.requirePrincipal(login);access.requireAnyRole(actor);
        if(!access.hasAnyRole(actor,Set.of(SecretRole.SECURITY,SecretRole.REMEDIATOR)))throw new ApiException(ErrorCode.FORBIDDEN);
        var rows=locations.visible(actor.userId(),null,new SecretInventoryFilters(origin,"ALL","ALL","ALL","ALL","ALL","ALL","ALL","ALL"));
        var items=new LinkedHashMap<Long,QueueItem>();
        var byCredential=new HashMap<Long,List<Map<String,Object>>>();
        for(var visible:rows)byCredential.computeIfAbsent(visible.secretId(),unused->new ArrayList<>()).add(read(visible.occurrenceId()));
        for(var visible:rows) {
            var row=read(visible.occurrenceId());String actual=bucket(row);if(!bucket.equals(actual))continue;
            if("NORMAL_INVENTORY".equals(bucket)&&byCredential.get(visible.secretId()).stream()
                .anyMatch(other->Set.of("ACTION_REQUIRED","NEEDS_DECISION","NEEDS_CASE_LINK").contains(bucket(other))))continue;
            long key="ACTION_REQUIRED".equals(bucket)?number(row,"case_id"):
                "NORMAL_INVENTORY".equals(bucket)?visible.secretId():visible.occurrenceId();
            String why="NEEDS_CASE_LINK".equals(bucket)?"ABNORMAL_LOCATION_UNLINKED":
                Boolean.TRUE.equals(row.get("requires_reassessment"))?"POLICY_REVIEW_REQUIRED":
                "ACTION_REQUIRED".equals(bucket)?"RESPONSE_REQUIRED":
                "METADATA_ONLY".equals(visible.componentState())?"METADATA_ONLY":
                "NORMAL_INVENTORY".equals(bucket)?"POLICY_ALLOWED_LOCATION":
                "UNCLASSIFIED".equals(origin)?"SOURCE_CLASSIFICATION_REQUIRED":"EVIDENCE_REVIEW_REQUIRED";
            String next="ACTION_REQUIRED".equals(bucket)?"OPEN_CASE":"NORMAL_INVENTORY".equals(bucket)?"VIEW_LOCATIONS":
                access.hasConnectionRole(actor,visible.connectionId(),SecretRole.SECURITY)?
                    "NEEDS_CASE_LINK".equals(bucket)?"LINK_CASE":"REVIEW_EVIDENCE":"VIEW_EVIDENCE";
            items.putIfAbsent(key,new QueueItem(visible.secretId(),visible.occurrenceId(),nullableNumber(row,"case_id"),origin,
                visible.maskedLabel(),visible.componentState(),text(row,"effective_presence"),visible.exposure(),why,next));
        }
        var all=new ArrayList<>(items.values());int from=(int)Math.min((long)page*size,all.size());
        return new QueuePage(all.subList(from,Math.min(from+size,all.size())),all.size(),page,size,
            "ACTION_REQUIRED".equals(bucket)?"ResponseCase":"NORMAL_INVENTORY".equals(bucket)?"CredentialSet":"Occurrence",
            jdbc.queryForObject("SELECT CURRENT_TIMESTAMP",OffsetDateTime.class),rows.stream().anyMatch(row->"UNKNOWN".equals(row.presence())),
            !access.hasGlobalRole(actor,SecretRole.SECURITY));
    }

    private ReviewContext project(SecretPrincipal actor,Map<String,Object> row) {
        long id=number(row,"occurrence_id");var reasons=allowedReasons(actor,row);
        var findings=jdbc.query("""
            SELECT f.*,EXISTS(SELECT 1 FROM secret_current_valid_findings v WHERE v.finding_id=f.finding_id) AS valid
            FROM secret_findings f WHERE f.occurrence_id=? AND f.run_id=? ORDER BY f.finding_id
            """,(rs,n)->new Finding(rs.getLong("finding_id"),rs.getString("rule_id"),rs.getString("rule_version"),
                rs.getObject("detected_at",OffsetDateTime.class),rs.getBoolean("valid")),id,row.get("last_seen_run_id"));
        var owners=reasons.containsKey("NEEDS_MORE_INFO")?jdbc.query("""
            SELECT DISTINCT u.user_id,u.display_name FROM dashboard_users u JOIN secret_role_grants g ON g.user_id=u.user_id
            WHERE g.role='SECURITY' AND g.revoked_at IS NULL AND (g.connection_id IS NULL OR g.connection_id=?)
            ORDER BY u.display_name,u.user_id
            """,(rs,n)->new Assignee(rs.getLong(1),rs.getString(2)),row.get("connection_id")):List.<Assignee>of();
        var latest=jdbc.queryForList("""
            SELECT a.assessment_id,a.version FROM secret_exposure_assessments a WHERE a.occurrence_id=?
              AND a.version=? AND a.decision='ABNORMAL' AND a.scope_version=? AND a.scope_revision=?
              AND a.policy_binding_id IS NOT DISTINCT FROM ?::bigint AND a.policy_version IS NOT DISTINCT FROM ?::bigint
            """,id,row.get("exposure_assessment_version"),row.get("response_origin_version"),row.get("revision"),row.get("binding_id"),row.get("policy_version"));
        var a=latest.isEmpty()?null:latest.getFirst();boolean repair=a!=null&&row.get("case_id")==null&&currentValue(row)
            &&!Boolean.TRUE.equals(row.get("requires_reassessment"))&&validFindings(id)>0
            &&access.hasConnectionRole(actor,number(row,"connection_id"),SecretRole.SECURITY);
        String validity=text(row,"validity_result"),reason=text(row,"validity_reason");
        var corrections=jdbc.query("""
            SELECT d.*,EXISTS(SELECT 1 FROM secret_current_raw_findings raw WHERE raw.finding_id=d.finding_id) AS current_finding,
              EXISTS(SELECT 1 FROM secret_current_valid_findings valid WHERE valid.finding_id=d.finding_id) AS still_valid
            FROM secret_finding_dispositions d WHERE d.occurrence_id=? ORDER BY d.created_at DESC,d.disposition_id DESC LIMIT 100
            """,(rs,n)-> {
                String recheck=rs.getObject("revoked_at")!=null?"APPROVAL_REVOKED":
                    !rs.getBoolean("is_current")?"REPLACED":!rs.getBoolean("current_finding")?"EVIDENCE_CHANGED":
                    !rs.getObject("reuse_expires_at",OffsetDateTime.class).isAfter(OffsetDateTime.now())?"APPROVAL_EXPIRED":
                    rs.getBoolean("still_valid")?"CONTRADICTORY_EVIDENCE":null;
                return new Correction(rs.getLong("disposition_id"),rs.getLong("finding_id"),rs.getLong("decision_id"),
                    rs.getString("decision_source"),rs.getObject("reuse_expires_at",OffsetDateTime.class),recheck==null,recheck);
            },id);
        return new ReviewContext(number(row,"credential_set_id"),id,number(row,"connection_id"),number(row,"scope_id"),
            number(row,"revision"),text(row,"response_origin"),text(row,"component_state"),text(row,"effective_presence"),
            text(row,"exposure_status"),text(row,"masked_label"),text(row,"issuer"),text(row,"credential_type"),"위치 #"+id,findings,
            new StoragePolicy(text(row,"policy_result"),nullableNumber(row,"policy_id"),nullableNumber(row,"policy_version"),
                nullableNumber(row,"binding_id"),text(row,"policy_reason"),Boolean.TRUE.equals(row.get("requires_reassessment"))),
            new Validity(validity==null?"UNCHECKED":validity,reason==null?"NO_VERIFICATION_ATTEMPT":
                SAFE_VALIDITY_REASONS.contains(reason)?reason:"UNSPECIFIED_REASON",time(row,"validity_at")),
            new Versions(number(row,"exposure_assessment_version"),number(row,"response_origin_version"),nullableNumber(row,"policy_version")),
            List.copyOf(reasons.keySet()),reasons,MISSING_REASONS.stream().sorted().toList(),owners,
            new CaseLinkData(nullableNumber(row,"case_id"),nullableNumber(row,"case_version"),text(row,"case_origin"),
                row.get("case_id")!=null?"LINKED":a!=null?"PENDING":"NOT_APPLICABLE",repair,
                a==null?null:number(a,"assessment_id"),a==null?null:number(a,"version")),corrections,unavailableReasons(actor,row,reasons));
    }

    private Map<String,String> unavailableReasons(SecretPrincipal actor,Map<String,Object> row,Map<String,List<String>> allowed) {
        var unavailable=new LinkedHashMap<String,String>();
        for(String decision:List.of("NORMAL","ABNORMAL","FALSE_POSITIVE","NEEDS_MORE_INFO")) {
            if(allowed.containsKey(decision))continue;
            String reason=!access.hasConnectionRole(actor,number(row,"connection_id"),SecretRole.SECURITY)?"SECURITY_ROLE_REQUIRED":
                "METADATA_ONLY".equals(row.get("component_state"))?"METADATA_NOT_EXPOSURE":
                !currentValue(row)?"CURRENT_PRESENCE_REQUIRED":validFindings(number(row,"occurrence_id"))==0?"CURRENT_FINDING_REQUIRED":
                "FALSE_POSITIVE".equals(decision)&&Boolean.TRUE.equals(row.get("confirmed_real"))?"REAL_CREDENTIAL_CONFIRMED":
                !"CONFIRMED".equals(row.get("component_state"))?"INCOMPLETE_CREDENTIAL":
                !Boolean.TRUE.equals(row.get("source_approved"))?"SOURCE_CLASSIFICATION_REQUIRED":
                "NORMAL".equals(decision)?"EXPLICIT_ALLOW_REQUIRED":"STORAGE_ALLOWED";
            unavailable.put(decision,reason);
        }
        return unavailable;
    }

    private Map<String,List<String>> allowedReasons(SecretPrincipal actor,Map<String,Object> row) {
        var allowed=new LinkedHashMap<String,List<String>>();
        if(!access.hasConnectionRole(actor,number(row,"connection_id"),SecretRole.SECURITY))return allowed;
        if("METADATA_ONLY".equals(row.get("component_state")))return allowed;
        long id=number(row,"occurrence_id");
        if(currentValue(row)&&validFindings(id)>0) {
            if("CONFIRMED".equals(row.get("component_state"))&&Boolean.TRUE.equals(row.get("source_approved"))) {
                if("ALLOWED".equals(row.get("policy_result")))allowed.put("NORMAL",List.of("POLICY_ALLOWED_LOCATION"));
                if("DENIED".equals(row.get("policy_result")))allowed.put("ABNORMAL",List.of("POLICY_PROHIBITED_LOCATION"));
                if("UNKNOWN".equals(row.get("policy_result")))allowed.put("ABNORMAL",List.of("UNAPPROVED_SOURCE_LOCATION"));
            }
            if(!Boolean.TRUE.equals(row.get("confirmed_real")))allowed.put("FALSE_POSITIVE",List.of("NOT_A_CREDENTIAL","DOCUMENTED_PLACEHOLDER"));
        }
        allowed.put("NEEDS_MORE_INFO",List.of("INSUFFICIENT_EVIDENCE"));
        return allowed;
    }

    private Map<String,Object> read(long id) {
        var row=jdbc.queryForList("""
            SELECT o.*,c.component_state,c.masked_label,c.issuer,c.credential_type,s.revision,s.response_origin,
                s.response_origin_version,s.enabled,p.binding_id,p.policy_id,p.policy_version,p.policy_result,
                EXISTS(SELECT 1 FROM secret_scope_origin_decisions source WHERE source.scope_id=s.scope_id
                    AND source.version=s.response_origin_version AND source.decision='APPROVED') AS source_approved,
                p.reason_code AS policy_reason,p.requires_reassessment,
                CASE WHEN NOT s.enabled THEN 'UNKNOWN'
                  WHEN latest.scope_outcome IN ('PARTIAL','FAILED','SKIPPED','UNKNOWN') AND latest.requested_at>o.last_seen_at
                    THEN 'UNKNOWN' ELSE o.presence_status END AS effective_presence,
                linked.case_id,linked.version AS case_version,linked.case_origin,linked.action_status,
                v.result AS validity_result,v.reason_code AS validity_reason,v.completed_at AS validity_at,
                EXISTS(SELECT 1 FROM secret_confirmed_real_credentials real WHERE real.credential_set_id=c.credential_set_id) AS confirmed_real
            FROM secret_occurrences o JOIN secret_credential_sets c ON c.credential_set_id=o.credential_set_id
            JOIN secret_connection_scopes s ON s.scope_id=o.scope_id
            JOIN secret_occurrence_policy_results p ON p.occurrence_id=o.occurrence_id
            LEFT JOIN LATERAL(SELECT outcome.scope_outcome,outcome.requested_at FROM secret_scope_outcomes outcome
                WHERE outcome.scope_id=s.scope_id AND outcome.scope_revision=s.revision AND outcome.job_kind='FULL_SCAN'
                ORDER BY outcome.requested_at DESC,outcome.run_id DESC LIMIT 1) latest ON TRUE
            LEFT JOIN LATERAL(SELECT rc.* FROM secret_case_occurrences co JOIN secret_response_cases rc ON rc.case_id=co.case_id
                WHERE co.occurrence_id=o.occurrence_id AND rc.is_current AND rc.case_origin=s.response_origin
                ORDER BY rc.case_id DESC LIMIT 1) linked ON TRUE
            LEFT JOIN LATERAL(SELECT attempt.* FROM secret_validation_attempts attempt JOIN secret_scan_runs run ON run.run_id=attempt.run_id
                WHERE attempt.credential_set_id=c.credential_set_id AND run.connection_id=o.connection_id
                 AND EXISTS(SELECT 1 FROM secret_findings f WHERE f.occurrence_id=o.occurrence_id AND f.run_id=attempt.run_id)
                ORDER BY attempt.completed_at DESC,attempt.attempt_id DESC LIMIT 1) v ON TRUE
            WHERE o.occurrence_id=?
            """,id).stream().findFirst().orElseThrow(()->new ApiException(ErrorCode.NOT_FOUND));
        // A command may have waited on a lock since the transaction's now(). Recheck real expiry.
        if(Set.of("ALLOWED","DENIED").contains(text(row,"policy_result"))) {
            String current=jdbc.queryForObject("""
                SELECT CASE WHEN status<>'ACTIVE' THEN 'POLICY_RETIRED'
                    WHEN valid_from>clock_timestamp() THEN 'POLICY_NOT_YET_VALID'
                    WHEN valid_until IS NOT NULL AND valid_until<=clock_timestamp() THEN 'POLICY_EXPIRED'
                    ELSE 'CURRENT' END FROM secret_storage_policies WHERE policy_id=? AND version=?
                """,String.class,row.get("policy_id"),row.get("policy_version"));
            if(!"CURRENT".equals(current)) {
                row.put("policy_result","UNKNOWN");row.put("policy_reason",current);
                if(!"UNKNOWN".equals(row.get("exposure_status")))row.put("requires_reassessment",true);
            }
        }
        return row;
    }

    private Map<String,Object> lock(SecretPrincipal actor,long id) {
        jdbc.queryForObject("SELECT pg_advisory_xact_lock(6197611306)",Object.class);
        var basis=read(id);authorize(actor,basis);
        jdbc.queryForObject("SELECT credential_set_id FROM secret_credential_sets WHERE credential_set_id=? FOR UPDATE",Long.class,basis.get("credential_set_id"));
        jdbc.queryForObject("SELECT scope_id FROM secret_connection_scopes WHERE scope_id=? FOR SHARE",Long.class,basis.get("scope_id"));
        // Shared order with location actions: current case before occurrence.
        jdbc.queryForList("SELECT case_id FROM secret_response_cases WHERE credential_set_id=? AND is_current ORDER BY case_id FOR UPDATE",basis.get("credential_set_id"));
        jdbc.queryForObject("SELECT occurrence_id FROM secret_occurrences WHERE occurrence_id=? FOR UPDATE",Long.class,id);
        var current=read(id);authorize(actor,current);return current;
    }
    private void authorize(SecretPrincipal actor,Map<String,Object> row) {
        access.requireOccurrenceRead(actor,number(row,"occurrence_id"));
        access.requireConnectionRole(actor,number(row,"connection_id"),SecretRole.SECURITY);
    }
    private void checkVersions(Map<String,Object> row,Long occurrence,Long scope,Long policy) {
        var changed=new ArrayList<String>();
        if(occurrence==null||occurrence!=number(row,"exposure_assessment_version"))changed.add("occurrence");
        if(scope==null||scope!=number(row,"response_origin_version"))changed.add("scope");
        if(!Objects.equals(policy,nullableNumber(row,"policy_version")))changed.add("policy");
        if(!changed.isEmpty())throw new SecretReviewConflict(changed.toArray(String[]::new));
    }
    private boolean currentValue(Map<String,Object> row) { return Boolean.TRUE.equals(row.get("enabled"))&&"PRESENT".equals(row.get("effective_presence")); }
    private long validFindings(long id) { return jdbc.queryForObject("SELECT count(*) FROM secret_current_valid_findings WHERE occurrence_id=?",Long.class,id); }
    private Map<String,Object> currentFinding(long id,long findingId) {
        return jdbc.queryForList("SELECT * FROM secret_current_valid_findings WHERE occurrence_id=? AND finding_id=?",id,findingId)
            .stream().findFirst().orElseThrow(()->new SecretReviewConflict("finding","presence"));
    }
    private long recordDecision(SecretPrincipal actor,Map<String,Object> row,Map<String,Object> finding,String decision,
        String reason,List<String> refs,long version) {
        return jdbc.queryForObject("""
            INSERT INTO secret_exposure_assessments(occurrence_id,finding_id,finding_rule_id,finding_run_id,finding_rule_version,
                from_status,decision,reason_code,scope_origin,actor_user_id,version,scope_version,scope_revision,
                policy_id,policy_version,policy_binding_id,policy_result,evidence_refs,observed_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?::jsonb,?) RETURNING assessment_id
            """,Long.class,row.get("occurrence_id"),finding==null?null:finding.get("finding_id"),finding==null?null:finding.get("rule_id"),
            finding==null?null:finding.get("run_id"),finding==null?null:finding.get("rule_version"),row.get("exposure_status"),decision,
            reason,row.get("response_origin"),actor.userId(),version,row.get("response_origin_version"),row.get("revision"),
            row.get("policy_id"),row.get("policy_version"),row.get("binding_id"),row.get("policy_result"),json.writeValueAsString(refs),
            finding==null?null:finding.get("detected_at"));
    }
    private long correct(SecretPrincipal actor,Map<String,Object> row,Map<String,Object> finding,long decision,String reason) {
        jdbc.update("UPDATE secret_finding_dispositions SET is_current=false WHERE finding_id=? AND is_current",finding.get("finding_id"));
        return jdbc.queryForObject("""
            INSERT INTO secret_finding_dispositions(decision_id,finding_id,occurrence_id,scope_id,scope_revision,scope_origin_version,scope_fingerprint,
                source_object_digest,location_digest,object_version,rule_id,rule_version,engine,engine_version,config_hash,
                protected_evidence_identity,identity_key_version,issuer,credential_type,reason_code,decision_source,reviewed_by_user_id,reuse_expires_at)
            SELECT ?,f.finding_id,o.occurrence_id,o.scope_id,?, ?,md5(jsonb_build_array(s.content_type,s.approved_ref,s.history_limit)::text),sha256(convert_to(o.source_object_ref,'UTF8')),
                sha256(convert_to(o.location_key,'UTF8')),o.latest_object_version,f.rule_id,f.rule_version,t.engine,t.engine_version,t.config_hash,
                coalesce(c.fingerprint,c.candidate_locator),c.fingerprint_key_version,c.issuer,c.credential_type,?,'HUMAN',?,now()+interval '30 days'
            FROM secret_findings f JOIN secret_tool_runs t ON t.tool_run_id=f.tool_run_id
            JOIN secret_occurrences o ON o.occurrence_id=f.occurrence_id JOIN secret_credential_sets c ON c.credential_set_id=o.credential_set_id
            JOIN secret_connection_scopes s ON s.scope_id=o.scope_id
            WHERE f.finding_id=? RETURNING disposition_id
            """,Long.class,decision,row.get("revision"),row.get("response_origin_version"),reason,actor.userId(),finding.get("finding_id"));
    }
    private record Link(Long caseId,String operation,Long version) { }
    private Link attach(SecretPrincipal actor,Map<String,Object> row,long decision,boolean repair) {
        var cases=jdbc.queryForList("""
            SELECT * FROM secret_response_cases WHERE credential_set_id=? AND case_origin=? AND is_current FOR UPDATE
            """,row.get("credential_set_id"),row.get("response_origin"));
        Map<String,Object> existing=cases.isEmpty()?null:cases.getFirst();
        if(existing!=null&&!allCaseSecurity(actor,number(existing,"case_id"))) {
            if(repair)throw new ApiException(ErrorCode.FORBIDDEN);
            return new Link(null,"NONE",null); // Retain the evidenced decision as a connection-bound repair task.
        }
        Long previous=null;boolean created=existing==null||"RESOLVED".equals(existing.get("action_status"));
        if(existing==null)previous=jdbc.query("SELECT case_id FROM secret_response_cases WHERE credential_set_id=? AND case_origin=? ORDER BY case_id DESC LIMIT 1",
            (rs,n)->rs.getLong(1),row.get("credential_set_id"),row.get("response_origin")).stream().findFirst().orElse(null);
        if(existing!=null&&created) {
            previous=number(existing,"case_id");
            jdbc.update("UPDATE secret_response_cases SET is_current=false,closed_at=now(),updated_at=now() WHERE case_id=?",previous);
        }
        long caseId,version;
        if(created) {
            caseId=jdbc.queryForObject("""
                INSERT INTO secret_response_cases(credential_set_id,previous_case_id,opening_occurrence_id,opened_by_user_id,
                    opening_reason,case_origin,review_status,opening_decision_id)
                VALUES(?,?,?,?,'ASSESSED_EXPOSURE',?,'REVIEWED',?) RETURNING case_id
                """,Long.class,row.get("credential_set_id"),previous,row.get("occurrence_id"),actor.userId(),row.get("response_origin"),decision);
            version=0;
            jdbc.update("""
                INSERT INTO secret_checklist_items(case_id,guide_version,item_code)
                SELECT ?,'S2_V1',code FROM (VALUES('IDENTIFY_OWNER'),('ROTATE_OR_REVOKE'),('REMOVE_EXPOSURE'),('CHECK_ACCESS_LOGS')) codes(code)
                ON CONFLICT DO NOTHING
                """,caseId);
            jdbc.update("INSERT INTO secret_audit_events(case_id,event_type,actor_user_id,case_version) VALUES(?,'CASE_OPENED',?,0)",caseId,actor.userId());
        } else {caseId=number(existing,"case_id");version=number(existing,"version");}
        int added=jdbc.update("""
            INSERT INTO secret_case_occurrences(case_id,occurrence_id,credential_set_id,linked_decision_id)
            VALUES(?,?,?,?) ON CONFLICT DO NOTHING
            """,caseId,row.get("occurrence_id"),row.get("credential_set_id"),decision);
        if(added==0)jdbc.update("UPDATE secret_case_occurrences SET linked_decision_id=? WHERE case_id=? AND occurrence_id=?",decision,caseId,row.get("occurrence_id"));
        if(!created&&added>0) {
            version++;
            boolean revalidate="REVALIDATION_PENDING".equals(existing.get("action_status"));
            jdbc.update("UPDATE secret_response_cases SET version=?,updated_at=now(),action_status=? WHERE case_id=?",version,
                revalidate?"IN_PROGRESS":existing.get("action_status"),caseId);
            if(revalidate)jdbc.update("""
                INSERT INTO secret_case_stage_history(case_id,from_status,to_status,reason_code,actor_user_id,case_version)
                VALUES(?,'REVALIDATION_PENDING','IN_PROGRESS','NEW_ABNORMAL_LOCATION',?,?)
                """,caseId,actor.userId(),version);
        }
        return new Link(caseId,created?"CREATED":"ATTACHED",version);
    }
    private boolean allCaseSecurity(SecretPrincipal actor,long caseId) {
        return jdbc.queryForList("SELECT o.connection_id FROM secret_case_occurrences co JOIN secret_occurrences o ON o.occurrence_id=co.occurrence_id WHERE co.case_id=?",caseId)
            .stream().allMatch(r->access.hasConnectionRole(actor,number(r,"connection_id"),SecretRole.SECURITY));
    }
    private String bucket(Map<String,Object> row) {
        if("METADATA_ONLY".equals(row.get("component_state")))return "NORMAL_INVENTORY";
        // A Finding correction or new investigation does not dismiss an existing response case.
        if(row.get("case_id")!=null&&!"RESOLVED".equals(row.get("action_status")))return "ACTION_REQUIRED";
        long id=number(row,"occurrence_id");
        long raw=jdbc.queryForObject("SELECT count(*) FROM secret_current_raw_findings WHERE occurrence_id=?",Long.class,id);
        if(raw>0&&validFindings(id)==0)return "EXCLUDED_HISTORY";
        if(Boolean.TRUE.equals(row.get("requires_reassessment")))return "NEEDS_DECISION";
        if("ABNORMAL".equals(row.get("exposure_status"))) {
            if(row.get("case_id")==null)return "NEEDS_CASE_LINK";
            return "RESOLVED".equals(row.get("action_status"))?"RESOLVED_HISTORY":"ACTION_REQUIRED";
        }
        if("NORMAL".equals(row.get("exposure_status"))&&"ALLOWED".equals(row.get("policy_result")))return "NORMAL_INVENTORY";
        return "NEEDS_DECISION";
    }

    /** Separate typed cache for the two decision commands; arbitrary request JSON is never persisted. */
    private DecisionResult execute(SecretPrincipal actor,long id,String kind,String key,byte[] digest,Supplier<DecisionResult> mutation) {
        if(key==null||!key.matches("[A-Za-z0-9._:-]{1,120}"))invalid();
        String hashed=HexFormat.of().formatHex(SecretEvidenceRules.digest(key));
        return Objects.requireNonNull(tx.execute(status->{
            long advisory=ByteBuffer.wrap(SecretEvidenceRules.digest(actor.userId(),kind,hashed)).getLong();
            jdbc.queryForObject("SELECT pg_advisory_xact_lock(?)",Object.class,advisory);
            authorize(actor,read(id));
            var prior=jdbc.queryForList("SELECT safe_request_digest,safe_result::text FROM secret_command_idempotency WHERE actor_user_id=? AND command_kind=? AND idempotency_key=?",actor.userId(),kind,hashed);
            if(!prior.isEmpty()) {
                if(!MessageDigest.isEqual((byte[])prior.getFirst().get("safe_request_digest"),digest))throw new ApiException(ErrorCode.CONFLICT);
                var result=json.readValue((String)prior.getFirst().get("safe_result"),DecisionResult.class);
                if(result.caseId()!=null&&!"NONE".equals(result.caseOperation())&&!allCaseSecurity(actor,result.caseId()))throw new ApiException(ErrorCode.FORBIDDEN);
                return result;
            }
            var result=mutation.get();
            long command=jdbc.queryForObject("""
                INSERT INTO secret_command_idempotency(actor_user_id,command_kind,idempotency_key,safe_request_digest,safe_result)
                VALUES(?,?,?,?,?::jsonb) RETURNING command_id
                """,Long.class,actor.userId(),kind,hashed,digest,json.writeValueAsString(result));
            jdbc.update("""
                INSERT INTO secret_audit_events(event_type,actor_user_id,target_type,target_id,target_version,command_id,safe_changes)
                SELECT ?,?,'OCCURRENCE',?,o.exposure_assessment_version,?,jsonb_build_object('decisionId',?::bigint,'caseOperation',?::text)
                FROM secret_occurrences o WHERE o.occurrence_id=?
                ""","CASE_LINK".equals(kind)?"CASE_LINKED":"TRIAGE_DECIDED",actor.userId(),id,command,result.decisionId(),result.caseOperation(),id);
            return result;
        }));
    }
    private static List<String> normalizeEvidence(List<String> refs) {
        if(refs==null)return List.of();if(refs.size()>8)invalid();refs.forEach(ref->reference(ref,true));
        return refs.stream().distinct().sorted().toList();
    }
    private static Long nullableNumber(Map<String,Object> row,String key) {return row.get(key)==null?null:((Number)row.get(key)).longValue();}
    private static String text(Map<String,Object> row,String key) {return row.get(key)==null?null:row.get(key).toString();}
    private static void expected(Long version) {if(version==null||version<0)invalid();}
    private static void invalid() {throw new ApiException(ErrorCode.INVALID_INPUT);}
}
