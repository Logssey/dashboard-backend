package com.logssey.secret.lifecycle;
import java.time.OffsetDateTime;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.command.*;
import com.logssey.secret.response.SecretLocationWorkflow;
import com.logssey.secret.snapshot.SecretReadSnapshots;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import static com.logssey.secret.snapshot.SecretReadSnapshots.facts;
import static com.logssey.secret.command.SecretCommandExecutor.requireExpectedVersion;
/** Immutable external records retain the reviewer relationship and provider-verification limits. */
@Service
public class SecretLifecycleService {
 public record Submission(String kind,OffsetDateTime performedAt,String evidenceRef,Long expectedCaseVersion,String idempotencyKey,Long sourceActionId){
  public Submission(String kind,OffsetDateTime performedAt,String evidenceRef,Long expectedCaseVersion,String idempotencyKey){this(kind,performedAt,evidenceRef,expectedCaseVersion,idempotencyKey,null);}
 }
 public record Review(String decision,String reasonCode,Long expectedEvidenceVersion,Long expectedCaseVersion,String idempotencyKey){}
 private static final Set<String> KINDS=Set.of("ROTATED","REVOKED","RETIRED","FIXTURE_RETIRED");
 private static final Map<String,List<String>> REASONS=Map.of("APPROVE",List.of("EXTERNAL_RECORD_CONFIRMED","SELF_ATTESTATION_LIMITED"),"REJECT",List.of("INSUFFICIENT_EVIDENCE","WRONG_CREDENTIAL","CONTRADICTORY_EVIDENCE"));
 private final JdbcTemplate jdbc;private final SecretAccessService access;private final SecretLocationWorkflow workflow;
 private final SecretCommandExecutor commands;private final SecretReadSnapshots snapshots;
 public SecretLifecycleService(JdbcTemplate jdbc,SecretAccessService access,SecretLocationWorkflow workflow,SecretCommandExecutor commands,SecretReadSnapshots snapshots){this.jdbc=jdbc;this.access=access;this.workflow=workflow;this.commands=commands;this.snapshots=snapshots;}
 @Transactional(readOnly=true)
 public Map<String,Object> list(long caseId,String login){
  var actor=access.requirePrincipal(login);var locations=workflow.visibleLocations(caseId,actor);if(locations.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);
  var c=jdbc.queryForMap("SELECT * FROM secret_response_cases WHERE case_id=?",caseId);var ids=locations.stream().map(o->num(o,"occurrence_id")).toList();
  var items=jdbc.queryForList("""
    SELECT e.*,1+(SELECT count(*) FROM secret_lifecycle_evidence_reviews WHERE evidence_id=e.evidence_id) AS current_version,
     r.decision AS review_decision,r.reason_code AS review_reason,r.reviewed_by_user_id,r.reviewed_at,
     coalesce(r.limitations @> '["SELF_ATTESTED"]'::jsonb,false) AS self_attested,
     coalesce(r.limitations @> '["ACTION_AUTHOR_REVIEWED"]'::jsonb,false) AS action_author_reviewed,
     EXISTS(SELECT 1 FROM secret_current_lifecycle_evidence current WHERE current.evidence_id=e.evidence_id) AS applicable
    FROM secret_credential_lifecycle_evidence e LEFT JOIN LATERAL(SELECT * FROM secret_lifecycle_evidence_reviews
     WHERE evidence_id=e.evidence_id ORDER BY review_id DESC LIMIT 1)r ON true WHERE e.case_id=? ORDER BY e.created_at DESC,e.evidence_id DESC
    """,caseId).stream().filter(e->ids.contains(num(e,"source_occurrence_id"))).map(e->{
     String level="PROVIDER_VERIFIED".equals(e.get("verification_level"))?"PROVIDER_VERIFIED":
       "APPROVE".equals(e.get("review_decision"))&&Boolean.TRUE.equals(e.get("self_attested"))?"SELF_ATTESTED":
       "APPROVE".equals(e.get("review_decision"))?"APPROVED_MANUAL":"REJECT".equals(e.get("review_decision"))?"REJECTED":"PENDING";
     boolean canReview=active(c)&&workflow.hasAllSecurity(actor,caseId)&&"EXTERNAL_RECORD".equals(e.get("verification_method"))&&!Objects.equals(e.get("submitted_by_user_id"),actor.userId());
     boolean canSelfAttest=active(c)&&"PENDING".equals(level)&&"EXTERNAL_RECORD".equals(e.get("verification_method"))&&Objects.equals(e.get("submitted_by_user_id"),actor.userId())&&singleReviewer(actor,caseId);
     boolean reviewingOwnAction=Objects.equals(e.get("source_action_recorded_by_user_id"),actor.userId());
     String reviewLevel=canReview?(reviewingOwnAction?"SELF_ATTESTED":"APPROVED_MANUAL"):canSelfAttest?"SELF_ATTESTED":null;
     return facts("evidenceId",e.get("evidence_id"),"caseId",caseId,"credentialSetId",c.get("credential_set_id"),"evidenceOrigin",e.get("origin"),
      "kind",e.get("kind"),"verificationMethod",e.get("verification_method"),"verificationLevel",level,
      "reviewStatus",level.equals("APPROVED_MANUAL")?"APPROVED":level,"performedAt",e.get("performed_at"),"observedAt",e.get("observed_at"),"sourceActionId",e.get("source_action_id"),
      "evidenceRef",e.get("evidence_ref"),"submittedByUserId",e.get("submitted_by_user_id"),"reviewedByUserId",e.get("reviewed_by_user_id"),
      "reviewedAt",e.get("reviewed_at"),"version",e.get("current_version"),"isCurrentlyApplicable",e.get("applicable"),
      "coverageLimit",level.equals("PROVIDER_VERIFIED")?"FULL":e.get("kind").equals("FIXTURE_RETIRED")?"SIMULATION":"LIMITED",
      "limitations",limitations(level,Boolean.TRUE.equals(e.get("action_author_reviewed"))),
      "reviewVerificationLevel",reviewLevel,"reviewLimitations",reviewLevel==null?List.of():limitations(reviewLevel,canReview&&reviewingOwnAction),
      "capabilities",facts("canReview",canReview,"canSelfAttest",canSelfAttest));
    }).toList();
  return facts("caseId",caseId,"caseVersion",c.get("version"),"items",items,"allowedKinds",synthetic(caseId)?List.of("FIXTURE_RETIRED"):List.of("ROTATED","REVOKED","RETIRED"),
    "allowedReviewReasonCodes",REASONS,"capabilities",facts("canSubmit",active(c)&&locations.stream().anyMatch(o->canSubmit(actor,caseId,num(o,"occurrence_id")))),
    "providerVerificationStatus","NOT_SUPPORTED_BY_CURRENT_VALIDATORS","sourceActions",sourceActions(caseId,actor,active(c)));
 }
 public Map<String,Object> submit(long caseId,Submission r,String login){
  var actor=access.requirePrincipal(login);
  if(r==null)invalid();
  if(r.sourceActionId()==null){
   if(!KINDS.contains(r.kind()==null?"":r.kind())||r.performedAt()==null||!safeRef(r.evidenceRef()))invalid();
  }else if(r.sourceActionId()<=0)invalid();
  var result=commands.execute(actor,SecretCommandExecutor.Kind.LIFECYCLE_SUBMIT,r.idempotencyKey(),digest(caseId,r),()->requireSubmit(actor,caseId),()->{
   var c=workflow.lockCase(caseId);requireExpectedVersion(r.expectedCaseVersion(),num(c,"version"));if(!active(c))conflict();
   var sources=workflow.visibleLocations(caseId,actor).stream().filter(o->canSubmit(actor,caseId,num(o,"occurrence_id"))).toList();
   if(sources.isEmpty())throw new ApiException(ErrorCode.FORBIDDEN);
   var action=r.sourceActionId()==null?matchingAction(caseId,sources.getFirst(),r):reusableAction(caseId,r.sourceActionId(),actor);
   String kind=action==null?r.kind():synthetic(caseId)?"FIXTURE_RETIRED":action.get("action_type").toString();
   OffsetDateTime performed=action==null?r.performedAt():actionTime(action);
   String reference=action==null?r.evidenceRef():action.get("evidence_ref").toString();
   if(action!=null&&r.kind()!=null&&!r.kind().equals(kind))invalid();
   if(action!=null){
    var existing=jdbc.queryForList("SELECT evidence_id,1+(SELECT count(*) FROM secret_lifecycle_evidence_reviews WHERE evidence_id=e.evidence_id) AS evidence_version,(SELECT decision FROM secret_lifecycle_evidence_reviews WHERE evidence_id=e.evidence_id ORDER BY review_id DESC LIMIT 1) AS review_decision FROM secret_credential_lifecycle_evidence e WHERE case_id=? AND source_action_id=?",caseId,action.get("action_id"));
    if(!existing.isEmpty()){
     var saved=existing.getFirst();
     var savedStatus="APPROVE".equals(saved.get("review_decision"))?SecretCommandResult.Status.APPROVED:
       "REJECT".equals(saved.get("review_decision"))?SecretCommandResult.Status.REJECTED:SecretCommandResult.Status.PENDING;
     return new SecretCommandResult(num(saved,"evidence_id"),num(saved,"evidence_version"),savedStatus);
    }
   }
   var source=sources.stream().filter(o->action==null||Objects.equals(o.get("occurrence_id"),action.get("occurrence_id"))).findFirst().orElseThrow(()->new ApiException(ErrorCode.FORBIDDEN));
   OffsetDateTime now=jdbc.queryForObject("SELECT clock_timestamp()",OffsetDateTime.class);
   if(performed.isAfter(now)||performed.isBefore(now.minusDays(90)))invalid();
   if("FIXTURE_RETIRED".equals(kind)!=synthetic(caseId))throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
   long id=jdbc.queryForObject("""
    INSERT INTO secret_credential_lifecycle_evidence(case_id,credential_set_id,source_occurrence_id,origin,kind,verification_method,
      verification_level,evidence_ref,performed_at,observed_at,submitted_by_user_id,source_action_id)
    VALUES(?,?,?,?,?,'EXTERNAL_RECORD','PENDING',?,?,?,?,?) RETURNING evidence_id
    """,Long.class,caseId,c.get("credential_set_id"),source.get("occurrence_id"),c.get("case_origin"),kind,reference,performed,now,actor.userId(),action==null?null:action.get("action_id"));
   bump(caseId);invalidate(caseId);activity(caseId,num(source,"occurrence_id"),"LIFECYCLE_SUBMITTED",actor.userId(),num(c,"version")+1,id);
   return new SecretCommandResult(id,1,SecretCommandResult.Status.PENDING);
  });return mutation(result);
 }
 public Map<String,Object> review(long caseId,long evidenceId,Review r,String login){
  var actor=access.requirePrincipal(login);if(r==null||!REASONS.getOrDefault(r.decision()==null?"":r.decision(),List.of()).contains(r.reasonCode()))invalid();
  var result=commands.execute(actor,SecretCommandExecutor.Kind.LIFECYCLE_REVIEW,r.idempotencyKey(),digest(caseId,evidenceId,r),()->requireReview(actor,caseId,evidenceId,r.reasonCode()),()->{
   var c=workflow.lockCase(caseId);requireExpectedVersion(r.expectedCaseVersion(),num(c,"version"));if(!active(c))conflict();
   var e=jdbc.queryForMap("SELECT * FROM secret_credential_lifecycle_evidence WHERE evidence_id=? AND case_id=? FOR UPDATE",evidenceId,caseId);
   requireReview(actor,caseId,evidenceId,r.reasonCode());
   long version=jdbc.queryForObject("SELECT 1+count(*) FROM secret_lifecycle_evidence_reviews WHERE evidence_id=?",Long.class,evidenceId);
   requireExpectedVersion(r.expectedEvidenceVersion(),version);
   if("SELF_ATTESTATION_LIMITED".equals(r.reasonCode())&&version!=1)throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
   if("APPROVE".equals(r.decision())&&(contradicted(num(e,"credential_set_id"),e.get("performed_at"))||("FIXTURE_RETIRED".equals(e.get("kind"))&&!synthetic(caseId))))throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
   jdbc.update("""
    INSERT INTO secret_lifecycle_evidence_reviews(evidence_id,decision,reason_code,expected_evidence_version,case_version,reviewed_by_user_id)
    VALUES(?,?,?,?,?,?)
    """,evidenceId,r.decision(),r.reasonCode(),version,num(c,"version")+1,actor.userId());
   if("APPROVE".equals(r.decision()))jdbc.update("""
    INSERT INTO secret_lifecycle_evidence_applications(evidence_id,case_id,credential_set_id,origin,reviewed_by_user_id)
    VALUES(?,?,?,?,?) ON CONFLICT(evidence_id,case_id) DO NOTHING
    """,evidenceId,caseId,c.get("credential_set_id"),c.get("case_origin"),actor.userId());
   bump(caseId);invalidate(caseId);activity(caseId,num(e,"source_occurrence_id"),"LIFECYCLE_REVIEWED",actor.userId(),num(c,"version")+1,evidenceId);
   return new SecretCommandResult(evidenceId,version+1,"APPROVE".equals(r.decision())?SecretCommandResult.Status.APPROVED:SecretCommandResult.Status.REJECTED);
  });return mutation(result);
 }
 public Map<String,Object> locationCheck(SecretPrincipal actor,long occurrence){
  access.requireOccurrenceRead(actor,occurrence);
  var rows=jdbc.queryForList("""
    SELECT e.evidence_id,e.verification_level,e.kind,e.observed_at,e.action_author_reviewed FROM secret_current_lifecycle_evidence e
    JOIN secret_case_occurrences co ON co.case_id=e.case_id AND co.occurrence_id=? JOIN secret_response_cases c ON c.case_id=e.case_id
    WHERE c.is_current AND e.source_occurrence_id=? ORDER BY e.observed_at DESC,e.evidence_id DESC LIMIT 1
    """,occurrence,occurrence);
  if(rows.isEmpty())return facts("status","UNKNOWN","reasonCode","LIFECYCLE_EVIDENCE_REQUIRED");
  var e=rows.getFirst();return facts("status","PASSED","reasonCode","FIXTURE_RETIRED".equals(e.get("kind"))?"SYNTHETIC_FIXTURE_REMOVAL":
    "PROVIDER_VERIFIED".equals(e.get("verification_level"))?"PROVIDER_RETIREMENT_CONFIRMED":"SELF_ATTESTED".equals(e.get("verification_level"))?"EXTERNAL_RECORD_SELF_ATTESTED":"EXTERNAL_RECORD_APPROVED",
    "verificationLevel",e.get("verification_level"),"evidenceId",e.get("evidence_id"),"observedAt",e.get("observed_at"),
    "limitations",limitations(e.get("verification_level").toString(),Boolean.TRUE.equals(e.get("action_author_reviewed"))),
    "coverageLimit","FIXTURE_RETIRED".equals(e.get("kind"))?"SIMULATION":"PROVIDER_VERIFIED".equals(e.get("verification_level"))?"FULL":"LIMITED");
 }
 public boolean assignedActionable(SecretPrincipal actor,long caseId,long occurrence){
  return workflow.assignedRemediator(actor,caseId,occurrence)&&Boolean.TRUE.equals(jdbc.queryForObject("""
   SELECT EXISTS(SELECT 1 FROM secret_case_occurrences co JOIN secret_response_cases c USING(case_id) WHERE case_id=? AND occurrence_id=?
    AND c.is_current AND c.disposition='IN_SCOPE' AND co.response_status IN ('OPEN','IN_PROGRESS'))
   """,Boolean.class,caseId,occurrence));
 }
 private void requireSubmit(SecretPrincipal actor,long caseId){if(workflow.visibleLocations(caseId,actor).stream().noneMatch(o->canSubmit(actor,caseId,num(o,"occurrence_id"))))throw new ApiException(ErrorCode.FORBIDDEN);}
 private boolean canSubmit(SecretPrincipal actor,long c,long o){var connection=jdbc.queryForObject("SELECT connection_id FROM secret_occurrences WHERE occurrence_id=?",Long.class,o);return access.hasConnectionRole(actor,connection,SecretRole.SECURITY)||workflow.assignedRemediator(actor,c,o);}
 private void requireReview(SecretPrincipal actor,long caseId,long id,String reason){
  if(!workflow.hasAllSecurity(actor,caseId))throw new ApiException(ErrorCode.FORBIDDEN);
  var rows=jdbc.queryForList("SELECT submitted_by_user_id,verification_method FROM secret_credential_lifecycle_evidence WHERE evidence_id=? AND case_id=?",id,caseId);
  if(rows.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);var e=rows.getFirst();
  boolean own=Objects.equals(e.get("submitted_by_user_id"),actor.userId());
  boolean self="SELF_ATTESTATION_LIMITED".equals(reason);
  if(!"EXTERNAL_RECORD".equals(e.get("verification_method"))||own!=self||self&&!singleReviewer(actor,caseId))throw new ApiException(ErrorCode.FORBIDDEN);
 }
 private boolean singleReviewer(SecretPrincipal actor,long caseId){
  return workflow.hasAllSecurity(actor,caseId)&&Long.valueOf(1).equals(jdbc.queryForObject("""
   SELECT count(*) FROM(SELECT DISTINCT user_id FROM secret_role_grants WHERE role='SECURITY' AND revoked_at IS NULL) reviewers
   WHERE NOT EXISTS(SELECT 1 FROM secret_case_occurrences co JOIN secret_occurrences o USING(occurrence_id)
    WHERE co.case_id=? AND NOT EXISTS(SELECT 1 FROM secret_role_grants g WHERE g.user_id=reviewers.user_id
     AND g.role='SECURITY' AND g.revoked_at IS NULL AND(g.connection_id IS NULL OR g.connection_id=o.connection_id)))
   """,Long.class,caseId));
 }
 private List<Map<String,Object>> sourceActions(long caseId,SecretPrincipal actor,boolean caseActive){
  boolean fixture=synthetic(caseId);
  OffsetDateTime now=jdbc.queryForObject("SELECT clock_timestamp()",OffsetDateTime.class);
  return jdbc.queryForList("""
    SELECT a.action_id,a.occurrence_id,a.action_type,a.performed_at,a.evidence_ref,e.evidence_id
    FROM secret_action_records a LEFT JOIN secret_credential_lifecycle_evidence e ON e.case_id=a.case_id AND e.source_action_id=a.action_id
    WHERE a.case_id=? AND a.action_type IN ('ROTATED','REVOKED') ORDER BY a.performed_at DESC,a.action_id DESC LIMIT 100
    """,caseId)
   .stream().filter(action->access.canReadOccurrence(actor,num(action,"occurrence_id"))&&canSubmit(actor,caseId,num(action,"occurrence_id")))
   .map(action->{
    String unavailable=!caseActive?"CASE_NOT_ACTIVE":action.get("evidence_id")!=null?"ACTION_ALREADY_SUBMITTED":
      actionTime(action).isAfter(now)?"ACTION_TIME_IN_FUTURE":actionTime(action).isBefore(now.minusDays(90))?"ACTION_TOO_OLD":null;
    return facts("actionId",action.get("action_id"),"occurrenceId",action.get("occurrence_id"),"actionType",action.get("action_type"),
      "lifecycleKind",fixture?"FIXTURE_RETIRED":action.get("action_type"),"performedAt",action.get("performed_at"),"evidenceRef",action.get("evidence_ref"),
      "reusable",unavailable==null,"unavailableReasonCode",unavailable,"existingEvidenceId",action.get("evidence_id"));
   }).toList();
 }
 private Map<String,Object> matchingAction(long caseId,Map<String,Object> source,Submission request){
  var matches=jdbc.queryForList("""
    SELECT * FROM secret_action_records WHERE case_id=? AND occurrence_id=? AND performed_at=? AND evidence_ref=?
     AND action_type IN ('ROTATED','REVOKED') AND(action_type=? OR ?='FIXTURE_RETIRED') ORDER BY action_id LIMIT 2
    """,caseId,source.get("occurrence_id"),request.performedAt(),request.evidenceRef(),request.kind(),request.kind());
  if(matches.size()>1)throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
  return matches.isEmpty()?null:matches.getFirst();
 }
 private static OffsetDateTime actionTime(Map<String,Object> action){
  Object value=action.get("performed_at");
  if(value instanceof OffsetDateTime timestamp)return timestamp;
  return ((java.sql.Timestamp)value).toInstant().atOffset(java.time.ZoneOffset.UTC);
 }
 private static List<String> limitations(String level,boolean actionAuthorReviewed){
  if("PROVIDER_VERIFIED".equals(level))return List.of();
  var result=new ArrayList<String>();
  result.add("PROVIDER_RETIREMENT_NOT_VERIFIED");
  if("SELF_ATTESTED".equals(level))result.add("SELF_ATTESTED");
  if(actionAuthorReviewed)result.add("ACTION_AUTHOR_REVIEWED");
  return List.copyOf(result);
 }
 private Map<String,Object> reusableAction(long caseId,long id,SecretPrincipal actor){
  var actions=jdbc.queryForList("SELECT * FROM secret_action_records WHERE case_id=? AND action_id=? AND action_type IN ('ROTATED','REVOKED')",caseId,id);
  if(actions.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);
  var action=actions.getFirst();
  if(!canSubmit(actor,caseId,num(action,"occurrence_id"))||!access.canReadOccurrence(actor,num(action,"occurrence_id")))throw new ApiException(ErrorCode.FORBIDDEN);
  return action;
 }
 private boolean synthetic(long caseId){return Boolean.TRUE.equals(jdbc.queryForObject("""
   SELECT c.case_origin='TEST' AND NOT EXISTS(SELECT 1 FROM secret_confirmed_real_credentials r WHERE r.credential_set_id=c.credential_set_id)
    AND EXISTS(SELECT 1 FROM secret_case_occurrences co WHERE co.case_id=c.case_id)
    AND NOT EXISTS(SELECT 1 FROM secret_case_occurrences co JOIN secret_occurrences o USING(occurrence_id) WHERE co.case_id=c.case_id
      AND NOT EXISTS(SELECT 1 FROM secret_current_fixture_attestations f WHERE f.credential_set_id=c.credential_set_id AND f.scope_id=o.scope_id))
   FROM secret_response_cases c WHERE c.case_id=?
   """,Boolean.class,caseId));}
 private boolean contradicted(long key,Object performed){return Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM secret_validation_attempts WHERE credential_set_id=? AND result='VALID' AND reason_code='AUTHENTICATED' AND provider_checked_at>?)",Boolean.class,key,performed));}
 private void invalidate(long c){jdbc.queryForList("SELECT occurrence_id FROM secret_case_occurrences WHERE case_id=?",Long.class,c).forEach(snapshots::invalidateOccurrence);}
 private void bump(long c){jdbc.update("UPDATE secret_response_cases SET version=version+1,updated_at=now() WHERE case_id=?",c);}
 private void activity(long c,long o,String type,long actor,long version,long id){jdbc.update("INSERT INTO secret_location_activities(case_id,occurrence_id,activity_type,actor_user_id,case_version,reference_id) VALUES(?,?,?,?,?,?)",c,o,type,actor,version,id);}
 private static boolean active(Map<String,Object> c){return Boolean.TRUE.equals(c.get("is_current"))&&"IN_SCOPE".equals(c.get("disposition"))&&!"RESOLVED".equals(c.get("action_status"));}
 private static boolean safeRef(String ref){return ref!=null&&ref.matches("(TICKET|CHANGE):[A-Z]{2,10}-[1-9][0-9]{0,9}");}
 private static Map<String,Object> mutation(SecretCommandResult r){return facts("evidenceId",r.targetId(),"version",r.version(),"status",r.status(),"requiresSnapshotRefresh",true);}
 private static long num(Map<String,Object> row,String k){return ((Number)row.get(k)).longValue();}
 private static byte[] digest(Object... values){try{return MessageDigest.getInstance("SHA-256").digest(Arrays.deepToString(values).getBytes(StandardCharsets.UTF_8));}catch(Exception e){throw new IllegalStateException(e);}}
 private static void invalid(){throw new ApiException(ErrorCode.INVALID_INPUT);}private static void conflict(){throw new ApiException(ErrorCode.CONFLICT);}
}
