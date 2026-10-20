package com.logssey.secret.alert;

import java.time.*;
import java.util.*;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.command.*;
import static com.logssey.secret.evidence.SecretEvidenceRules.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service @Transactional(readOnly=true)
public class SecretCrossEnvironmentAlertService {
 private final JdbcTemplate jdbc;private final SecretAccessService access;private final SecretCommandExecutor commands;
 public SecretCrossEnvironmentAlertService(JdbcTemplate jdbc,SecretAccessService access,SecretCommandExecutor commands){this.jdbc=jdbc;this.access=access;this.commands=commands;}
 private static final Set<String> ACK=Set.of("INVESTIGATION_STARTED","OWNER_NOTIFIED","EVIDENCE_REVIEWED");
 private static final Set<String> CLOSE=Set.of("VERIFIED_SYNTHETIC","ALL_FINDINGS_FALSE_POSITIVE","CREDENTIAL_RETIRED");

 public Map<String,Object> list(String login,String status,String owner,int page,int size){
  code(status,Set.of("OPEN","ALL","SUSPECTED_REAL","CONFIRMED_REAL","CLOSED"));code(owner,Set.of("ME","ALL"));page(page,size);
  var actor=access.requirePrincipal(login);access.requireAnyRole(actor);List<Map<String,Object>> items=new ArrayList<>();
  for(var a:jdbc.queryForList("SELECT a.*,u.display_name AS assignee_display_name FROM secret_cross_environment_alerts a LEFT JOIN dashboard_users u ON u.user_id=a.assignee_user_id ORDER BY a.last_observed_at DESC,a.alert_id DESC")){
   var locations=visibleLocations(actor,number(a,"alert_id"));if(locations.isEmpty())continue;
   if(owner.equals("ME")&&!Objects.equals(a.get("assignee_user_id"),actor.userId()))continue;
   if(status.equals("OPEN")&&a.get("closed_at")!=null||!Set.of("OPEN","ALL").contains(status)&&!status.equals(a.get("status")))continue;
   items.add(projection(actor,a,locations,false));
  }
  int from=(int)Math.min((long)page*size,items.size()),to=Math.min(from+size,items.size());
  return Map.of("items",items.subList(from,to),"total",items.size(),"page",page,"size",size,"unit","CrossEnvironmentAlert","asOf",OffsetDateTime.now(ZoneOffset.UTC));
 }
 public Map<String,Object> detail(String login,long id){var actor=access.requirePrincipal(login);var a=read(id,false);var locations=visibleLocations(actor,id);if(locations.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);return projection(actor,a,locations,true);}
 public Map<String,Object> assign(String login,long id,SecretCrossEnvironmentAlertRequests.Assignment r){
  if(r==null||r.assigneeUserId()!=null&&r.assigneeUserId()<=0)throw new ApiException(ErrorCode.INVALID_INPUT);code(r.reasonCode(),ASSIGNMENT_REASONS);future(r.dueAt(),false);
  var actor=access.requirePrincipal(login);requireManage(actor,id);
  var result=commands.execute(actor,SecretCommandExecutor.Kind.CROSS_ALERT_ASSIGN,r.idempotencyKey(),digest(id,r.assigneeUserId(),r.dueAt(),r.reasonCode(),r.expectedVersion()),()->requireManage(actor,id),()->{
   var a=read(id,true);requireOpen(a);SecretCommandExecutor.requireExpectedVersion(r.expectedVersion(),number(a,"version"));
   if(r.assigneeUserId()!=null&&!canManage(new SecretPrincipal(r.assigneeUserId()),id))throw new ApiException(ErrorCode.INVALID_INPUT);
   if(r.assigneeUserId()==null&&!Set.of("UNASSIGNED","DUE_DATE_CHANGE").contains(r.reasonCode()))throw new ApiException(ErrorCode.INVALID_INPUT);
   jdbc.update("UPDATE secret_cross_environment_alerts SET assignee_user_id=?,due_at=?,version=version+1 WHERE alert_id=?",r.assigneeUserId(),r.dueAt(),id);
   Map<String,Object> changed=new LinkedHashMap<>();changed.put("reasonCode",r.reasonCode());changed.put("assigneeUserId",r.assigneeUserId());changed.put("dueAt",r.dueAt());
   history(id,"ASSIGNMENT_CHANGED",actor.userId(),number(a,"version")+1,changed);
   return new SecretCommandResult(id,number(a,"version")+1,SecretCommandResult.Status.OPEN);
  });return mutation("alertId",result);
 }
 public Map<String,Object> acknowledge(String login,long id,SecretCrossEnvironmentAlertRequests.Acknowledge r){
  if(r==null)throw new ApiException(ErrorCode.INVALID_INPUT);code(r.reasonCode(),ACK);var actor=access.requirePrincipal(login);requireManage(actor,id);
  var result=commands.execute(actor,SecretCommandExecutor.Kind.CROSS_ALERT_ACK,r.idempotencyKey(),digest(id,r.reasonCode(),r.expectedVersion()),()->requireManage(actor,id),()->{
   var a=read(id,true);requireOpen(a);SecretCommandExecutor.requireExpectedVersion(r.expectedVersion(),number(a,"version"));
   jdbc.update("UPDATE secret_cross_environment_alerts SET acknowledged_at=clock_timestamp(),version=version+1 WHERE alert_id=?",id);
   history(id,"ACKNOWLEDGED",actor.userId(),number(a,"version")+1,Map.of("reasonCode",r.reasonCode()));
   return new SecretCommandResult(id,number(a,"version")+1,SecretCommandResult.Status.OPEN);
  });return mutation("alertId",result);
 }
 public Map<String,Object> close(String login,long id,SecretCrossEnvironmentAlertRequests.Close r){
  if(r==null)throw new ApiException(ErrorCode.INVALID_INPUT);code(r.reasonCode(),CLOSE);var fixtureIds=ids(r.fixtureAttestationIds());var correctionIds=ids(r.correctionIds());var lifecycleIds=ids(r.lifecycleEvidenceIds());
  var actor=access.requirePrincipal(login);requireManage(actor,id);
  var result=commands.execute(actor,SecretCommandExecutor.Kind.CROSS_ALERT_CLOSE,r.idempotencyKey(),digest(id,r.expectedVersion(),r.reasonCode(),fixtureIds,correctionIds,lifecycleIds,r.caseId(),r.investigationTaskId()),()->requireManage(actor,id),()->{
   var a=read(id,true);requireOpen(a);SecretCommandExecutor.requireExpectedVersion(r.expectedVersion(),number(a,"version"));
   if(r.caseId()==null&&r.investigationTaskId()==null||r.caseId()!=null&&!Objects.equals(a.get("test_case_id"),r.caseId())
      ||r.investigationTaskId()!=null&&!Objects.equals(a.get("investigation_task_id"),r.investigationTaskId()))throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
   var closure=closureEvidence(a);boolean accepted=false;
   if(r.reasonCode().equals("VERIFIED_SYNTHETIC")&&a.get("status").equals("SUSPECTED_REAL")){
    var evidence=(List<Map<String,Object>>)closure.get("fixtureAttestations");
    boolean allLocations=allLocations(id).stream().allMatch(l->evidence.stream().anyMatch(e->Objects.equals(e.get("scopeId"),l.get("scope_id"))&&fixtureIds.contains(e.get("attestationId"))));
    accepted=allLocations&&!fixtureIds.isEmpty()&&evidence.stream().map(e->(Long)e.get("attestationId")).collect(java.util.stream.Collectors.toSet()).containsAll(fixtureIds);
   }else if(r.reasonCode().equals("ALL_FINDINGS_FALSE_POSITIVE")&&a.get("status").equals("SUSPECTED_REAL")){
    accepted=allCurrentFindingsCorrected(id,correctionIds);
   }else if(r.reasonCode().equals("CREDENTIAL_RETIRED")&&a.get("status").equals("CONFIRMED_REAL")){
    var eligible=(List<Map<String,Object>>)closure.get("lifecycleEvidence");
    accepted=!lifecycleIds.isEmpty()&&eligible.stream().map(e->(Long)e.get("evidenceId")).collect(java.util.stream.Collectors.toSet()).containsAll(lifecycleIds);
   }
   if(!accepted)throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
   String snapshot=tools.jackson.databind.json.JsonMapper.builder().build().writeValueAsString(Map.of("reasonCode",r.reasonCode(),"fixtureAttestationIds",fixtureIds,"correctionIds",correctionIds,"lifecycleEvidenceIds",lifecycleIds));
   jdbc.update("UPDATE secret_cross_environment_alerts SET status='CLOSED',closed_at=clock_timestamp(),closure_evidence_snapshot=?::jsonb,version=version+1 WHERE alert_id=?",snapshot,id);
   history(id,"CLOSED",actor.userId(),number(a,"version")+1,Map.of("reasonCode",r.reasonCode()));
   return new SecretCommandResult(id,number(a,"version")+1,SecretCommandResult.Status.CLOSED);
  });return mutation("alertId",result);
 }
 private Map<String,Object> read(long id,boolean lock){return jdbc.queryForList("SELECT a.*,u.display_name AS assignee_display_name FROM secret_cross_environment_alerts a LEFT JOIN dashboard_users u ON u.user_id=a.assignee_user_id WHERE a.alert_id=?"+(lock?" FOR UPDATE OF a":""),id).stream().findFirst().orElseThrow(()->new ApiException(ErrorCode.NOT_FOUND));}
 private static void requireOpen(Map<String,Object> a){if(a.get("closed_at")!=null)throw new ApiException(ErrorCode.CONFLICT);}
 private List<Map<String,Object>> allLocations(long id){return jdbc.queryForList("""
  SELECT l.occurrence_id,l.first_observed_at,l.last_observed_at,o.scope_id,o.connection_id,s.revision,s.safe_display_alias,fs.fixture_status
  FROM secret_cross_environment_alert_locations l JOIN secret_occurrences o ON o.occurrence_id=l.occurrence_id
  JOIN secret_connection_scopes s ON s.scope_id=o.scope_id JOIN secret_test_fixture_status fs ON fs.occurrence_id=o.occurrence_id
  WHERE l.alert_id=? ORDER BY l.occurrence_id
  """,id);}
 private List<Map<String,Object>> visibleLocations(SecretPrincipal actor,long id){return allLocations(id).stream().filter(l->access.hasConnectionRole(actor,number(l,"connection_id"),SecretRole.SECURITY)).toList();}
 private boolean canManage(SecretPrincipal actor,long id){var all=allLocations(id);return !all.isEmpty()&&all.stream().allMatch(l->access.hasConnectionRole(actor,number(l,"connection_id"),SecretRole.SECURITY));}
 private void requireManage(SecretPrincipal actor,long id){if(!canManage(actor,id))throw new ApiException(ErrorCode.FORBIDDEN);}
 private Map<String,Object> closureEvidence(Map<String,Object> a){
  long id=number(a,"alert_id"),key=number(a,"credential_set_id");List<Map<String,Object>> fixtures=new ArrayList<>(),corrections=new ArrayList<>(),lifecycle=new ArrayList<>();
  for(var e:jdbc.queryForList("""
   SELECT DISTINCT f.attestation_id,f.scope_id,f.scope_revision,f.manifest_id,f.manifest_version,f.confirmed_at
   FROM secret_current_fixture_attestations f JOIN secret_cross_environment_alert_locations l ON l.alert_id=?
   JOIN secret_occurrences o ON o.occurrence_id=l.occurrence_id AND o.scope_id=f.scope_id
   WHERE f.credential_set_id=? ORDER BY f.attestation_id
   """,id,key))fixtures.add(Map.of("attestationId",e.get("attestation_id"),"scopeId",e.get("scope_id"),"scopeRevision",e.get("scope_revision"),"manifestId",e.get("manifest_id"),"manifestVersion",e.get("manifest_version"),"confirmedAt",time(e,"confirmed_at")));
  if(tableExists("secret_finding_corrections")){
   for(var e:jdbc.queryForList("""
    SELECT c.correction_id,c.finding_id,COALESCE((to_jsonb(c)->>'corrected_at')::timestamptz,(to_jsonb(c)->>'created_at')::timestamptz) AS corrected_at
    FROM secret_finding_corrections c JOIN secret_findings f ON f.finding_id=c.finding_id
    JOIN secret_exposure_assessments d ON d.assessment_id=c.decision_id
    JOIN secret_cross_environment_alert_locations l ON l.occurrence_id=f.occurrence_id AND l.alert_id=?
    WHERE d.decision='FALSE_POSITIVE' AND d.occurrence_id=f.occurrence_id AND (to_jsonb(c)->>'revoked_at') IS NULL
      AND ((to_jsonb(c)->>'expires_at') IS NULL OR (to_jsonb(c)->>'expires_at')::timestamptz>CURRENT_TIMESTAMP)
    """,id)){Map<String,Object> correction=new LinkedHashMap<>();correction.put("correctionId",e.get("correction_id"));correction.put("findingId",e.get("finding_id"));correction.put("correctedAt",time(e,"corrected_at"));corrections.add(correction);}
  }
  if(tableExists("secret_credential_lifecycle_evidence")){
   for(var e:jdbc.queryForList("""
    SELECT evidence_id,kind,verification_level,observed_at FROM secret_credential_lifecycle_evidence e
    WHERE credential_set_id=? AND kind IN ('ROTATED','REVOKED','RETIRED')
     AND verification_level IN ('APPROVED_MANUAL','PROVIDER_VERIFIED')
     AND NOT EXISTS(SELECT 1 FROM secret_validation_attempts v WHERE v.credential_set_id=e.credential_set_id
        AND v.result='VALID' AND v.provider_checked_at>e.performed_at)
    ORDER BY evidence_id DESC
    """,key))lifecycle.add(Map.of("evidenceId",e.get("evidence_id"),"kind",e.get("kind"),"verificationLevel",e.get("verification_level"),"observedAt",time(e,"observed_at")));
  }
  return Map.of("fixtureAttestations",fixtures,"corrections",corrections,"lifecycleEvidence",lifecycle);
 }
 private boolean allCurrentFindingsCorrected(long id,List<Long> supplied){
  if(supplied.isEmpty()||!tableExists("secret_finding_corrections"))return false;
  var a=read(id,false);var eligible=(List<Map<String,Object>>)closureEvidence(a).get("corrections");
  if(!eligible.stream().map(e->(Long)e.get("correctionId")).collect(java.util.stream.Collectors.toSet()).containsAll(supplied))return false;
  var active=jdbc.queryForObject("""
   SELECT count(*) FROM secret_current_valid_findings f JOIN secret_cross_environment_alert_locations l ON l.occurrence_id=f.occurrence_id WHERE l.alert_id=?
   """,Long.class,id);if(active!=0)return false;
  var findings=jdbc.queryForList("""
   SELECT f.finding_id FROM secret_findings f JOIN secret_occurrences o ON o.occurrence_id=f.occurrence_id
   JOIN secret_cross_environment_alert_locations l ON l.occurrence_id=o.occurrence_id AND l.alert_id=? WHERE f.run_id=o.last_seen_run_id
   """,Long.class,id);
  return !findings.isEmpty()&&findings.stream().allMatch(f->eligible.stream().anyMatch(e->Objects.equals(e.get("findingId"),f)&&supplied.contains(e.get("correctionId"))));
 }
 private Map<String,Object> projection(SecretPrincipal actor,Map<String,Object> a,List<Map<String,Object>> locations,boolean detail){
  Map<String,Object> p=new LinkedHashMap<>();String[][] fields={{"alertId","alert_id"},{"credentialSetId","credential_set_id"},{"status","status"},{"assigneeUserId","assignee_user_id"},{"assigneeDisplayName","assignee_display_name"},{"version","version"}};
  for(var n:fields)p.put(n[0],a.get(n[1]));p.put("dueAt",time(a,"due_at"));p.put("acknowledgedAt",time(a,"acknowledged_at"));p.put("closedAt",time(a,"closed_at"));
  boolean manage=canManage(actor,number(a,"alert_id"));p.put("testCaseId",manage?a.get("test_case_id"):null);
  Object task=a.get("investigation_task_id");if(task!=null){var target=jdbc.queryForList("SELECT occurrence_id FROM secret_investigation_tasks WHERE task_id=?",task).getFirst();
   if(target.get("occurrence_id")!=null&&locations.stream().noneMatch(l->Objects.equals(l.get("occurrence_id"),target.get("occurrence_id"))))task=null;}
  p.put("investigationTaskId",task);
  p.put("firstObservedAt",locations.stream().map(l->time(l,"first_observed_at")).min(OffsetDateTime::compareTo).orElse(null));p.put("lastObservedAt",locations.stream().map(l->time(l,"last_observed_at")).max(OffsetDateTime::compareTo).orElse(null));
  p.put("restrictedCoverage",!access.hasGlobalRole(actor,SecretRole.SECURITY));
  p.put("nextActionCode",a.get("assignee_user_id")==null||a.get("due_at")==null?"ASSIGN_INVESTIGATION":"REVIEW_TEST_EVIDENCE");
  p.put("locations",locations.stream().map(l->Map.of("occurrenceId",l.get("occurrence_id"),"scopeId",l.get("scope_id"),"safeDisplayAlias",l.get("safe_display_alias")==null?"위치 #"+l.get("occurrence_id"):l.get("safe_display_alias"),"fixtureStatus",l.get("fixture_status"))).toList());
  Map<String,Object> eligible=manage?closureEvidence(a):Map.of("fixtureAttestations",List.of(),"corrections",List.of(),"lifecycleEvidence",List.of());List<String> allowed=new ArrayList<>();
  if(a.get("status").equals("SUSPECTED_REAL")){
   var fixtures=(List<Map<String,Object>>)eligible.get("fixtureAttestations");if(!fixtures.isEmpty()&&locations.stream().allMatch(l->fixtures.stream().anyMatch(f->Objects.equals(f.get("scopeId"),l.get("scope_id")))))allowed.add("VERIFIED_SYNTHETIC");
   var corrections=(List<Map<String,Object>>)eligible.get("corrections");if(!corrections.isEmpty()&&allCurrentFindingsCorrected(number(a,"alert_id"),corrections.stream().map(c->(Long)c.get("correctionId")).toList()))allowed.add("ALL_FINDINGS_FALSE_POSITIVE");
  }else if(a.get("status").equals("CONFIRMED_REAL")&&!((List<?>)eligible.get("lifecycleEvidence")).isEmpty())allowed.add("CREDENTIAL_RETIRED");
  boolean open=a.get("closed_at")==null;p.put("capabilities",Map.of("canAssign",open&&manage,"canAcknowledge",open&&manage,"canClose",open&&manage&&!allowed.isEmpty()));
  if(detail){p.put("eligibleClosureEvidence",eligible);p.put("allowedClosureReasonCodes",allowed);p.put("allowedAcknowledgementReasonCodes",ACK);p.put("allowedAssignmentReasonCodes",ASSIGNMENT_REASONS);
   p.put("eligibleAssignees",manage?jdbc.queryForList("SELECT user_id,display_name FROM dashboard_users ORDER BY display_name,user_id").stream().filter(u->canManage(new SecretPrincipal(number(u,"user_id")),number(a,"alert_id"))).map(u->Map.of("userId",u.get("user_id"),"displayName",u.get("display_name"))).toList():List.of());
  }return p;
 }
 private static List<Long> ids(List<Long> values){if(values==null)return List.of();if(values.size()>100||values.stream().anyMatch(v->v==null||v<=0)||new HashSet<>(values).size()!=values.size())throw new ApiException(ErrorCode.INVALID_INPUT);return values.stream().sorted().toList();}
 private boolean tableExists(String name){return jdbc.queryForObject("SELECT to_regclass(?) IS NOT NULL",Boolean.class,name);}
 private void history(long id,String event,Long actor,long version,Map<String,Object> changes){jdbc.update("INSERT INTO secret_cross_environment_alert_history(alert_id,event_type,actor_user_id,safe_changes,alert_version) VALUES(?,?,?,?::jsonb,?)",id,event,actor,tools.jackson.databind.json.JsonMapper.builder().build().writeValueAsString(changes),version);}
}
