package com.logssey.secret.risk;

import java.time.*;
import java.util.*;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.command.SecretCommandExecutor;
import com.logssey.secret.evidence.SecretEvidenceRules;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class SecretRiskEvidenceService {
    public record Submission(Long expectedEvidenceRevision,String idempotencyKey,String evidenceType,String subject,OffsetDateTime observedAt,OffsetDateTime validUntil,String evidenceRef,Map<String,Object> facts){}
    public record Decision(Long expectedEvidenceRevision,String idempotencyKey,String decision,String reasonCode){}
    final JdbcTemplate jdbc; final SecretAccessService access; final SecretRiskCommands commands;
    public SecretRiskEvidenceService(JdbcTemplate jdbc,SecretAccessService access,SecretRiskCommands commands){this.jdbc=jdbc;this.access=access;this.commands=commands;}
    public Map<String,Object> submit(String login,long occurrence,Submission r){
        if(r==null||r.expectedEvidenceRevision()==null)throw SecretRiskFacts.invalid();
        var actor=access.requirePrincipal(login);access.requireOccurrenceRead(actor,occurrence);
        var facts=SecretRiskFacts.validate(r.evidenceType(),r.subject(),r.facts());
        SecretRiskFacts.window(r.evidenceType(),r.observedAt(),r.validUntil(),OffsetDateTime.now(ZoneOffset.UTC));
        SecretEvidenceRules.reference(r.evidenceRef(),true);
        var safe=new ArrayList<Object>(Arrays.asList(occurrence,r.expectedEvidenceRevision(),r.evidenceType(),r.observedAt(),r.validUntil(),r.evidenceRef(),facts));
        return commands.execute(actor,"RISK_EVIDENCE_SUBMITTED",r.idempotencyKey(),safe,()->access.requireOccurrenceRead(actor,occurrence),()->{
            var o=lock(occurrence,r.expectedEvidenceRevision());boolean accepted=access.hasConnectionRole(actor,number(o,"connection_id"),SecretRole.SECURITY);
            if(!accepted&&!access.hasConnectionRole(actor,number(o,"connection_id"),SecretRole.REMEDIATOR))throw new ApiException(ErrorCode.FORBIDDEN);
            String payload=commands.json.writeValueAsString(facts);
            long id=jdbc.queryForObject("""
                INSERT INTO secret_risk_evidence(record_kind,kind,occurrence_id,credential_set_id,scope_id,source_kind,verification_level,
                 safe_payload,observed_at,effective_from,expires_at,submitted_by_user_id,reviewed_by_user_id,reason_code,evidence_ref,
                 safe_payload_digest,ingestion_key,credential_revision,scope_revision,source_object_version,identity_binding_status,mapping_version)
                VALUES('ASSERTION',?,?,?,?,'MANUAL',?,?::jsonb,?,?,?,?,?,'EVIDENCE_SUBMITTED',?,?,?,?,?,?,?,'manual-evidence-v1') RETURNING evidence_id
                """,Long.class,r.evidenceType(),occurrence,number(o,"credential_set_id"),number(o,"scope_id"),accepted?"MANUAL_ACCEPTED":"MANUAL_SUBMITTED",payload,
                r.observedAt(),r.observedAt(),r.validUntil(),actor.userId(),accepted?actor.userId():null,r.evidenceRef(),SecretRiskCommands.digest(payload),
                HexFormat.of().formatHex(SecretRiskCommands.digest(actor.userId()+":"+r.idempotencyKey())),number(o,"credential_revision"),number(o,"revision"),o.get("latest_object_version"),facts.getOrDefault("identityBindingStatus","NOT_APPLICABLE"));
            return result(occurrence,id,accepted?"ACCEPTED":"PENDING");
        });
    }
    public Map<String,Object> decide(String login,long occurrence,long evidence,Decision r){
        if(r==null||r.expectedEvidenceRevision()==null||r.decision()==null||r.reasonCode()==null||!SecretRiskFacts.EVIDENCE_DECISIONS.contains(r.decision())||!SecretRiskFacts.EVIDENCE_REASONS.contains(r.reasonCode()))throw SecretRiskFacts.invalid();
        var actor=access.requirePrincipal(login);authorize(actor,occurrence);
        return commands.execute(actor,"RISK_EVIDENCE_DECIDED",r.idempotencyKey(),List.of(occurrence,evidence,r.expectedEvidenceRevision(),r.decision(),r.reasonCode()),()->authorize(actor,occurrence),()->{
            lock(occurrence,r.expectedEvidenceRevision());
            var rows=jdbc.queryForList("SELECT * FROM secret_risk_evidence WHERE evidence_id=? AND occurrence_id=? AND record_kind='ASSERTION'",evidence,occurrence);
            if(rows.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);
            if(Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM secret_risk_evidence WHERE related_evidence_id=? AND record_kind='RETRACTION')",Boolean.class,evidence)))throw new ApiException(ErrorCode.CONFLICT);
            var e=rows.getFirst();
            if("ACCEPT".equals(r.decision())&&e.get("expires_at")!=null&&!((java.sql.Timestamp)e.get("expires_at")).toInstant().isAfter(Instant.now()))throw new ApiException(ErrorCode.UNPROCESSABLE);
            long id=jdbc.queryForObject("""
                INSERT INTO secret_risk_evidence(record_kind,kind,occurrence_id,credential_set_id,scope_id,related_evidence_id,source_kind,
                 verification_level,safe_payload,observed_at,effective_from,expires_at,submitted_by_user_id,reviewed_by_user_id,
                 review_decision,reason_code,evidence_ref,safe_payload_digest,ingestion_key,credential_revision,scope_revision)
                VALUES(?,?,?,?,?,?,'MANUAL','MANUAL_ACCEPTED','{}',?,?,?,?,?,?,?,?,?,?,?,?) RETURNING evidence_id
                """,Long.class,r.decision().equals("RETRACT")?"RETRACTION":"REVIEW",e.get("kind"),occurrence,e.get("credential_set_id"),e.get("scope_id"),evidence,
                e.get("observed_at"),e.get("effective_from"),e.get("expires_at"),actor.userId(),actor.userId(),r.decision().equals("RETRACT")?null:r.decision(),r.reasonCode(),e.get("evidence_ref"),
                SecretRiskCommands.digest("{}"),HexFormat.of().formatHex(SecretRiskCommands.digest(actor.userId()+":"+r.idempotencyKey())),e.get("credential_revision"),e.get("scope_revision"));
            return result(occurrence,id,r.decision().equals("ACCEPT")?"ACCEPTED":r.decision().equals("REJECT")?"REJECTED":"RETRACTED");
        });
    }
    void authorize(SecretPrincipal actor,long occurrence){access.requireOccurrenceRead(actor,occurrence);access.requireConnectionRole(actor,jdbc.queryForObject("SELECT connection_id FROM secret_occurrences WHERE occurrence_id=?",Long.class,occurrence),SecretRole.SECURITY);}
    Map<String,Object> lock(long occurrence,Long expected){var o=jdbc.queryForMap("SELECT o.*,c.credential_revision,s.revision FROM secret_occurrences o JOIN secret_credential_sets c USING(credential_set_id) JOIN secret_connection_scopes s USING(scope_id) WHERE o.occurrence_id=? FOR UPDATE OF o",occurrence);SecretCommandExecutor.requireExpectedVersion(expected,number(o,"risk_evidence_revision"));return o;}
    Map<String,Object> result(long occurrence,long id,String status){return Map.of("occurrenceId",occurrence,"evidenceId",id,"status",status,"evidenceRevision",jdbc.queryForObject("SELECT risk_evidence_revision FROM secret_occurrences WHERE occurrence_id=?",Long.class,occurrence),"requiresSnapshotRefresh",true);}
    static long number(Map<String,Object> r,String key){return ((Number)r.get(key)).longValue();}
}
