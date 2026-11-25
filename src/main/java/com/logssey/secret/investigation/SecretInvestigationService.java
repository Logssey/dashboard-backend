package com.logssey.secret.investigation;
import com.logssey.secret.evidence.SecretInternalRecord;

import java.time.*;
import java.util.*;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.command.*;
import static com.logssey.secret.evidence.SecretEvidenceRules.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Service
@Transactional(readOnly=true)
public class SecretInvestigationService {
 private final JdbcTemplate jdbc;private final SecretAccessService access;private final SecretCommandExecutor commands;
 public SecretInvestigationService(JdbcTemplate jdbc,SecretAccessService access,SecretCommandExecutor commands){this.jdbc=jdbc;this.access=access;this.commands=commands;}
 private static final String SELECT="""
  SELECT t.*,COALESCE(t.scope_id,o.scope_id) AS resolved_scope_id,s.connection_id,s.revision,s.safe_display_alias,
      o.credential_set_id,u.display_name AS assignee_display_name
  FROM secret_investigation_tasks t LEFT JOIN secret_occurrences o ON o.occurrence_id=t.occurrence_id
  JOIN secret_connection_scopes s ON s.scope_id=COALESCE(t.scope_id,o.scope_id)
  LEFT JOIN dashboard_users u ON u.user_id=t.assignee_user_id
  """;

 public Map<String,Object> list(String login,String status,String owner,int page,int size){
  page(page,size);code(status,Set.of("OPEN","OVERDUE","CLOSED","ALL"));code(owner,Set.of("ME","ALL"));
  var actor=access.requirePrincipal(login);access.requireAnyRole(actor);List<Map<String,Object>> items=new ArrayList<>();
  for(var row:jdbc.queryForList(SELECT+" ORDER BY t.created_at DESC,t.task_id DESC")){
   if(!canRead(actor,row)||owner.equals("ME")&&!Objects.equals(row.get("assignee_user_id"),actor.userId()))continue;
   boolean overdue="OPEN".equals(row.get("status"))&&time(row,"due_at")!=null&&time(row,"due_at").isBefore(OffsetDateTime.now(ZoneOffset.UTC));
   if(status.equals("OVERDUE")&&!overdue||!Set.of("OVERDUE","ALL").contains(status)&&!status.equals(row.get("status")))continue;
   items.add(projection(actor,row,false));
  }
  long total=items.size();int from=(int)Math.min((long)page*size,total),to=Math.min(from+size,items.size());
  return Map.of("items",items.subList(from,to),"total",total,"page",page,"size",size,"unit","InvestigationTask","asOf",OffsetDateTime.now(ZoneOffset.UTC));
 }
 public Map<String,Object> detail(String login,long taskId){var actor=access.requirePrincipal(login);var task=read(taskId,false);requireRead(actor,task);return projection(actor,task,true);}

 @Transactional
 public Map<String,Object> request(String login,SecretInvestigationRequests.Request r){
  if(r==null||r.targetId()==null||r.targetId()<=0)throw new ApiException(ErrorCode.INVALID_INPUT);
  code(r.targetType(),Set.of("SCOPE","OCCURRENCE"));
  code(r.missingReasonCode(),Set.of("SOURCE_CLASSIFICATION","POLICY_UNKNOWN","OWNER_UNKNOWN","SOURCE_PERMISSION","EVIDENCE_INCOMPLETE"));
  if(r.targetType().equals("OCCURRENCE")&&r.missingReasonCode().equals("SOURCE_CLASSIFICATION"))throw new ApiException(ErrorCode.INVALID_INPUT);
  future(r.dueAt(),false);reference(r.evidenceRef(),false);
  var actor=access.requirePrincipal(login);
  var result=commands.execute(actor,SecretCommandExecutor.Kind.INVESTIGATION_REQUEST,r.idempotencyKey(),
   digest(r.targetType(),r.targetId(),r.missingReasonCode(),r.assigneeUserId(),r.dueAt(),r.evidenceRef(),r.expectedTargetVersion()),
   ()->requestTarget(actor,r.targetType(),r.targetId(),false),()->{
    var target=requestTarget(actor,r.targetType(),r.targetId(),true);
    SecretCommandExecutor.requireExpectedVersion(r.expectedTargetVersion(),number(target,"target_version"));
    validateOwner(target,r.assigneeUserId());
    String field=r.targetType().equals("SCOPE")?"scope_id":"occurrence_id";
    var existing=jdbc.queryForList("SELECT task_id FROM secret_investigation_tasks WHERE "+field+"=? AND missing_reason_code=? AND status='OPEN' FOR UPDATE",r.targetId(),r.missingReasonCode());
    if(!existing.isEmpty()){
     var task=read(number(existing.getFirst(),"task_id"),false);requireRead(actor,task);
     return new SecretCommandResult(number(task,"task_id"),number(task,"version"),SecretCommandResult.Status.OPEN);
    }
    long id=jdbc.queryForObject("INSERT INTO secret_investigation_tasks(target_type,"+field+",missing_reason_code,creation_source,requested_by_user_id,assignee_user_id,due_at,evidence_ref) VALUES(?,?,?,'HUMAN_HANDOFF',?,?,?,?) RETURNING task_id",
     Long.class,r.targetType(),r.targetId(),r.missingReasonCode(),actor.userId(),r.assigneeUserId(),r.dueAt(),r.evidenceRef());
    history(id,"REQUESTED",actor.userId(),0,r.evidenceRef(),"missingReasonCode",r.missingReasonCode());
    return new SecretCommandResult(id,0,SecretCommandResult.Status.OPEN);
   });return mutation("taskId",result);
 }

 private Map<String,Object> requestTarget(SecretPrincipal actor,String type,long id,boolean lock){
  var target=jdbc.queryForList(type.equals("SCOPE")?
   "SELECT connection_id,scope_id,response_origin_version AS target_version,'SCOPE' AS target_type FROM secret_connection_scopes WHERE scope_id=?"+(lock?" FOR UPDATE":""):
   "SELECT connection_id,scope_id,exposure_assessment_version AS target_version,'OCCURRENCE' AS target_type FROM secret_occurrences WHERE occurrence_id=?"+(lock?" FOR UPDATE":""),id)
   .stream().findFirst().orElseThrow(()->new ApiException(ErrorCode.NOT_FOUND));
  if(type.equals("SCOPE"))access.requireConnectionFactsRead(actor,number(target,"connection_id"));else access.requireOccurrenceRead(actor,id);
  return target;
 }

 @Transactional
 public Map<String,Object> acceptEvidence(String login,long id,SecretInvestigationRequests.AcceptEvidence r){
  if(r==null||r.historyId()==null)throw new ApiException(ErrorCode.INVALID_INPUT);
  var actor=access.requirePrincipal(login);
  var result=commands.execute(actor,SecretCommandExecutor.Kind.INVESTIGATION_ACCEPT,r.idempotencyKey(),digest(id,r.historyId(),r.expectedVersion()),
   ()->{var t=read(id,false);requireRead(actor,t);access.requireConnectionRole(actor,number(t,"connection_id"),SecretRole.SECURITY);},()->{
    var task=read(id,true);requireOpen(task);SecretCommandExecutor.requireExpectedVersion(r.expectedVersion(),number(task,"version"));
    if(!Set.of("OWNER_UNKNOWN","EVIDENCE_INCOMPLETE").contains(task.get("missing_reason_code")))throw new ApiException(ErrorCode.INVALID_INPUT);
    var evidence=jdbc.queryForList("SELECT * FROM secret_investigation_history WHERE task_id=? AND history_id=? AND event_type='EVIDENCE_ADDED'",id,r.historyId())
      .stream().findFirst().orElseThrow(()->new ApiException(ErrorCode.EVIDENCE_REQUIRED));
    var evidenceKind=tools.jackson.databind.json.JsonMapper.builder().build().readTree(evidence.get("safe_changes").toString()).path("evidenceKind").asText();
    if(task.get("missing_reason_code").equals("OWNER_UNKNOWN")&&!evidenceKind.equals("OWNER_CONFIRMATION"))throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
    jdbc.update("UPDATE secret_investigation_tasks SET version=version+1 WHERE task_id=?",id);
    historyChanges(id,"EVIDENCE_ACCEPTED",actor.userId(),number(task,"version")+1,(String)evidence.get("evidence_ref"),Map.of("acceptedHistoryId",r.historyId()));
    return new SecretCommandResult(id,number(task,"version")+1,SecretCommandResult.Status.OPEN);
   });return mutation("taskId",result);
 }

 @Transactional
 public Map<String,Object> assign(String login,long id,SecretInvestigationRequests.Assignment r){
  if(r==null)throw new ApiException(ErrorCode.INVALID_INPUT);code(r.reasonCode(),ASSIGNMENT_REASONS);future(r.dueAt(),false);
  var actor=access.requirePrincipal(login);var initial=read(id,false);requireRead(actor,initial);
  var result=commands.execute(actor,SecretCommandExecutor.Kind.INVESTIGATION_ASSIGN,r.idempotencyKey(),
   digest(id,r.assigneeUserId(),r.dueAt(),r.reasonCode(),r.expectedVersion()),()->requireRead(actor,read(id,false)),()->{
    var task=read(id,true);requireOpen(task);SecretCommandExecutor.requireExpectedVersion(r.expectedVersion(),number(task,"version"));
    boolean required="HUMAN_MORE_INFO".equals(task.get("creation_source"))||Boolean.TRUE.equals(task.get("human_follow_up_required"));
    if(required&&(r.assigneeUserId()==null||r.dueAt()==null))throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
    validateOwner(task,r.assigneeUserId());
    if(r.assigneeUserId()==null&&!Set.of("UNASSIGNED","DUE_DATE_CHANGE").contains(r.reasonCode()))throw new ApiException(ErrorCode.INVALID_INPUT);
    jdbc.update("UPDATE secret_investigation_tasks SET assignee_user_id=?,due_at=?,version=version+1 WHERE task_id=?",r.assigneeUserId(),r.dueAt(),id);
    Map<String,Object> changed=new LinkedHashMap<>();changed.put("reasonCode",r.reasonCode());changed.put("assigneeUserId",r.assigneeUserId());changed.put("dueAt",r.dueAt());
    historyChanges(id,"ASSIGNMENT_CHANGED",actor.userId(),number(task,"version")+1,null,changed);
    return new SecretCommandResult(id,number(task,"version")+1,SecretCommandResult.Status.OPEN);
   });return mutation("taskId",result);
 }
 @Transactional
 public Map<String,Object> evidence(String login,long id,SecretInvestigationRequests.Evidence r){
  if(r==null)throw new ApiException(ErrorCode.INVALID_INPUT);reference(r.evidenceRef(),false);code(r.evidenceKind(),EVIDENCE_KINDS);observed(r.observedAt());
  var actor=access.requirePrincipal(login);requireRead(actor,read(id,false));
  var result=commands.execute(actor,SecretCommandExecutor.Kind.INVESTIGATION_EVIDENCE,r.idempotencyKey(),
   digest(id,r.evidenceRef(),r.evidenceKind(),r.observedAt(),r.expectedVersion()),()->requireRead(actor,read(id,false)),()->{
    var task=read(id,true);requireOpen(task);SecretCommandExecutor.requireExpectedVersion(r.expectedVersion(),number(task,"version"));
    String reference=SecretInternalRecord.reference(jdbc,r.evidenceRef(),actor.userId(),"INVESTIGATION",id,number(task,"version")+1,"EVIDENCE_ADDED");
    jdbc.update("UPDATE secret_investigation_tasks SET evidence_ref=?,version=version+1 WHERE task_id=?",reference,id);
    historyChanges(id,"EVIDENCE_ADDED",actor.userId(),number(task,"version")+1,reference,Map.of("evidenceKind",r.evidenceKind(),"observedAt",r.observedAt()));
    return new SecretCommandResult(id,number(task,"version")+1,SecretCommandResult.Status.OPEN);
   });return mutation("taskId",result);
 }
 @Transactional
 public Map<String,Object> close(String login,long id,SecretInvestigationRequests.Close r){
  if(r==null||java.util.stream.Stream.of(r.resolvingDecisionId(),r.restoredRunScopeId(),r.scopeOriginDecisionId(),r.policyBindingId(),r.acceptedEvidenceHistoryId()).filter(Objects::nonNull).count()!=1)throw new ApiException(ErrorCode.INVALID_INPUT);
  var actor=access.requirePrincipal(login);requireRead(actor,read(id,false));
  var result=commands.execute(actor,SecretCommandExecutor.Kind.INVESTIGATION_CLOSE,r.idempotencyKey(),digest(id,r.expectedVersion(),r.resolvingDecisionId(),r.restoredRunScopeId(),r.scopeOriginDecisionId(),r.policyBindingId(),r.acceptedEvidenceHistoryId()),
   ()->requireRead(actor,read(id,false)),()->{
    var task=read(id,true);requireOpen(task);SecretCommandExecutor.requireExpectedVersion(r.expectedVersion(),number(task,"version"));
    var eligible=closureEvidence(task);String key=r.resolvingDecisionId()!=null?"decisions":r.restoredRunScopeId()!=null?"runScopes":r.scopeOriginDecisionId()!=null?"scopeDecisions":r.policyBindingId()!=null?"policyBindings":"acceptedEvidence";
    String idField=r.resolvingDecisionId()!=null?"decisionId":r.restoredRunScopeId()!=null?"runScopeId":r.scopeOriginDecisionId()!=null?"scopeOriginDecisionId":r.policyBindingId()!=null?"policyBindingId":"historyId";
    Long evidence=r.resolvingDecisionId()!=null?r.resolvingDecisionId():r.restoredRunScopeId()!=null?r.restoredRunScopeId():r.scopeOriginDecisionId()!=null?r.scopeOriginDecisionId():r.policyBindingId()!=null?r.policyBindingId():r.acceptedEvidenceHistoryId();
    if(((List<Map<String,Object>>)eligible.get(key)).stream().noneMatch(e->Objects.equals(e.get(idField),evidence)))throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
    jdbc.update("UPDATE secret_investigation_tasks SET status='CLOSED',closed_at=clock_timestamp(),resolving_decision_id=?,restored_run_scope_id=?,scope_origin_decision_id=?,policy_binding_id=?,accepted_evidence_history_id=?,version=version+1 WHERE task_id=?",r.resolvingDecisionId(),r.restoredRunScopeId(),r.scopeOriginDecisionId(),r.policyBindingId(),r.acceptedEvidenceHistoryId(),id);
    String kind=r.resolvingDecisionId()!=null?"DECISION":r.restoredRunScopeId()!=null?"SCOPE_RESTORED":r.scopeOriginDecisionId()!=null?"SCOPE_CLASSIFIED":r.policyBindingId()!=null?"POLICY_APPLIED":"EVIDENCE_ACCEPTED";
    history(id,"CLOSED",actor.userId(),number(task,"version")+1,null,"resolutionKind",kind);
    return new SecretCommandResult(id,number(task,"version")+1,SecretCommandResult.Status.CLOSED);
   });return mutation("taskId",result);
 }

 /** Called by the single-decision command within its transaction; creation never makes an exposure decision. */
 @Transactional
 public long createHumanTaskTx(SecretPrincipal actor,long occurrenceId,String missingReasonCode,long assigneeUserId,OffsetDateTime dueAt,String evidenceRef){
  if(!TransactionSynchronizationManager.isActualTransactionActive())throw new IllegalStateException("TRANSACTION_REQUIRED");
  code(missingReasonCode,MISSING_REASONS);future(dueAt,true);reference(evidenceRef,false);
  var target=jdbc.queryForList("SELECT o.connection_id,o.scope_id FROM secret_occurrences o WHERE o.occurrence_id=? FOR UPDATE",occurrenceId)
   .stream().findFirst().orElseThrow(()->new ApiException(ErrorCode.NOT_FOUND));
  access.requireConnectionRole(actor,number(target,"connection_id"),SecretRole.SECURITY);
  Map<String,Object> context=new HashMap<>(target);context.put("target_type","OCCURRENCE");validateOwner(context,assigneeUserId);
  var existing=jdbc.queryForList("SELECT task_id,version FROM secret_investigation_tasks WHERE occurrence_id=? AND missing_reason_code=? AND status='OPEN' FOR UPDATE",occurrenceId,missingReasonCode);
  long id,version;
  if(existing.isEmpty()){
   id=jdbc.queryForObject("""
    INSERT INTO secret_investigation_tasks(target_type,occurrence_id,missing_reason_code,creation_source,assignee_user_id,due_at,evidence_ref,human_follow_up_required)
    VALUES('OCCURRENCE',?,?,'HUMAN_MORE_INFO',?,?,?,true) RETURNING task_id
    """,Long.class,occurrenceId,missingReasonCode,assigneeUserId,dueAt,evidenceRef);version=0;
  }else{id=number(existing.getFirst(),"task_id");version=number(existing.getFirst(),"version")+1;
   jdbc.update("UPDATE secret_investigation_tasks SET assignee_user_id=?,due_at=?,evidence_ref=?,human_follow_up_required=true,version=? WHERE task_id=?",assigneeUserId,dueAt,evidenceRef,version,id);
  }
  history(id,"HUMAN_FOLLOW_UP_REQUESTED",actor.userId(),version,evidenceRef,"missingReasonCode",missingReasonCode);return id;
 }

 private Map<String,Object> read(long id,boolean lock){return jdbc.queryForList(SELECT+" WHERE t.task_id=?"+(lock?" FOR UPDATE OF t":""),id).stream().findFirst().orElseThrow(()->new ApiException(ErrorCode.NOT_FOUND));}
 private boolean canRead(SecretPrincipal actor,Map<String,Object> task){long connection=number(task,"connection_id");return access.hasConnectionRole(actor,connection,SecretRole.SECURITY)
  ||"SCOPE".equals(task.get("target_type"))&&access.hasConnectionRole(actor,connection,SecretRole.OPERATIONS)
  ||"HUMAN_HANDOFF".equals(task.get("creation_source"))&&Objects.equals(task.get("requested_by_user_id"),actor.userId())
     &&task.get("occurrence_id")!=null&&access.canReadOccurrence(actor,number(task,"occurrence_id"));}
 private void requireRead(SecretPrincipal actor,Map<String,Object> task){if(!canRead(actor,task))throw new ApiException(ErrorCode.NOT_FOUND);}
 private static void requireOpen(Map<String,Object> task){if(!task.get("status").equals("OPEN"))throw new ApiException(ErrorCode.CONFLICT);}
 private void validateOwner(Map<String,Object> task,Long owner){
  if(owner==null)return;if(owner<=0)throw new ApiException(ErrorCode.INVALID_INPUT);boolean valid=access.hasConnectionRole(new SecretPrincipal(owner),number(task,"connection_id"),SecretRole.SECURITY)
    ||"SCOPE".equals(task.get("target_type"))&&access.hasConnectionRole(new SecretPrincipal(owner),number(task,"connection_id"),SecretRole.OPERATIONS);
  if(!valid)throw new ApiException(ErrorCode.INVALID_INPUT);
 }
 private List<Map<String,Object>> eligibleOwners(Map<String,Object> task){
  return jdbc.queryForList("SELECT user_id,display_name FROM dashboard_users ORDER BY display_name,user_id").stream().filter(u->{
   try{validateOwner(task,number(u,"user_id"));return true;}catch(ApiException denied){return false;}
  }).map(u->Map.<String,Object>of("userId",u.get("user_id"),"displayName",u.get("display_name"))).toList();
 }
 private Map<String,Object> closureEvidence(Map<String,Object> task){
  List<Map<String,Object>> decisions=new ArrayList<>(),runs=new ArrayList<>();
  if(task.get("target_type").equals("OCCURRENCE")&&!Set.of("SOURCE_PERMISSION","SOURCE_CLASSIFICATION","OWNER_UNKNOWN","EVIDENCE_INCOMPLETE").contains(task.get("missing_reason_code"))){
   for(var r:jdbc.queryForList("""
    SELECT a.assessment_id,a.decision,a.assessed_at FROM secret_exposure_assessments a
    JOIN secret_occurrences o ON o.occurrence_id=a.occurrence_id JOIN secret_connection_scopes s ON s.scope_id=o.scope_id
    JOIN secret_occurrence_policy_results policy ON policy.occurrence_id=o.occurrence_id
    WHERE a.occurrence_id=? AND a.version=o.exposure_assessment_version
      AND a.assessed_at>=? AND a.scope_origin=s.response_origin
      AND a.scope_version=s.response_origin_version AND a.scope_revision=s.revision
      AND ((a.decision IN ('NORMAL','ABNORMAL') AND a.decision=o.exposure_status
        AND NOT policy.requires_reassessment
        AND a.policy_binding_id IS NOT DISTINCT FROM policy.binding_id
        AND a.policy_version IS NOT DISTINCT FROM policy.policy_version)
       OR (a.decision='FALSE_POSITIVE'
        AND EXISTS(SELECT 1 FROM secret_current_raw_findings raw WHERE raw.occurrence_id=o.occurrence_id)
        AND NOT EXISTS(SELECT 1 FROM secret_current_valid_findings valid WHERE valid.occurrence_id=o.occurrence_id)
        AND EXISTS(SELECT 1 FROM secret_finding_dispositions correction WHERE correction.decision_id=a.assessment_id
          AND correction.is_current AND correction.revoked_at IS NULL AND correction.reuse_expires_at>CURRENT_TIMESTAMP)))
    ORDER BY a.assessment_id DESC
    """,task.get("occurrence_id"),task.get("created_at")))decisions.add(Map.of("decisionId",r.get("assessment_id"),"decision",r.get("decision"),"decidedAt",time(r,"assessed_at")));
  }
  if(task.get("missing_reason_code").equals("SOURCE_PERMISSION")){
   for(var r:jdbc.queryForList("""
    SELECT so.run_scope_id,so.run_id,so.finished_at FROM secret_scope_outcomes so JOIN secret_connection_scopes s ON s.scope_id=so.scope_id
    WHERE so.scope_id=? AND so.scope_revision=s.revision AND s.enabled AND so.scope_outcome='SUCCEEDED'
      AND so.job_kind='FULL_SCAN' AND so.job_status='SUCCEEDED' AND so.finished_at>=? AND so.requested_at>=? ORDER BY so.run_scope_id DESC
    """,task.get("resolved_scope_id"),task.get("created_at"),task.get("created_at")))runs.add(Map.of("runScopeId",r.get("run_scope_id"),"runId",r.get("run_id"),"finishedAt",time(r,"finished_at")));
  }
  List<Map<String,Object>> origins=new ArrayList<>(),bindings=new ArrayList<>(),accepted=new ArrayList<>();
  if(task.get("missing_reason_code").equals("SOURCE_CLASSIFICATION"))
   for(var r:jdbc.queryForList("""
    SELECT d.decision_id,d.decided_at FROM secret_scope_origin_decisions d JOIN secret_connection_scopes s USING(scope_id)
    WHERE d.scope_id=? AND d.version=s.response_origin_version AND d.decision='APPROVED' AND d.decided_at>=? ORDER BY d.decision_id DESC
    """,task.get("resolved_scope_id"),task.get("created_at")))origins.add(Map.of("scopeOriginDecisionId",r.get("decision_id"),"decidedAt",time(r,"decided_at")));
  if(task.get("missing_reason_code").equals("POLICY_UNKNOWN"))
   for(var r:jdbc.queryForList("""
    SELECT b.binding_id,b.effective_from FROM secret_scope_policy_bindings b
    JOIN secret_storage_policies p ON p.policy_id=b.policy_id AND p.version=b.policy_version
    JOIN secret_connection_scopes s USING(scope_id)
    WHERE b.scope_id=? AND b.effective_until IS NULL AND b.effective_from>=? AND p.status='ACTIVE'
      AND p.valid_from<=now() AND (p.valid_until IS NULL OR p.valid_until>now())
      AND EXISTS(SELECT 1 FROM secret_storage_policy_rules r WHERE r.policy_id=b.policy_id AND r.policy_version=b.policy_version
        AND r.scope_id=s.scope_id AND r.scope_revision=s.revision AND r.scope_fingerprint=md5(jsonb_build_array(s.content_type,s.approved_ref,s.history_limit)::text))
    """,task.get("resolved_scope_id"),task.get("created_at")))bindings.add(Map.of("policyBindingId",r.get("binding_id"),"effectiveFrom",time(r,"effective_from")));
  if(Set.of("OWNER_UNKNOWN","EVIDENCE_INCOMPLETE").contains(task.get("missing_reason_code")))
   for(var r:jdbc.queryForList("""
    SELECT h.history_id,h.created_at FROM secret_investigation_history h WHERE h.task_id=? AND h.event_type='EVIDENCE_ACCEPTED'
      AND EXISTS(SELECT 1 FROM secret_role_grants g WHERE g.user_id=h.actor_user_id AND g.role='SECURITY'
        AND g.revoked_at IS NULL AND (g.connection_id IS NULL OR g.connection_id=?)) ORDER BY h.history_id DESC
    """,task.get("task_id"),task.get("connection_id")))accepted.add(Map.of("historyId",r.get("history_id"),"acceptedAt",time(r,"created_at")));
  return Map.of("decisions",decisions,"runScopes",runs,"scopeDecisions",origins,"policyBindings",bindings,"acceptedEvidence",accepted);
 }
 private Map<String,Object> projection(SecretPrincipal actor,Map<String,Object> t,boolean detail){
  Map<String,Object> p=new LinkedHashMap<>();
  String[][] fields={{"taskId","task_id"},{"targetType","target_type"},{"occurrenceId","occurrence_id"},{"scopeId","resolved_scope_id"},{"credentialSetId","credential_set_id"},{"connectionId","connection_id"},{"missingReasonCode","missing_reason_code"},{"creationSource","creation_source"},{"assigneeUserId","assignee_user_id"},{"assigneeDisplayName","assignee_display_name"},{"status","status"},{"version","version"},{"evidenceRef","evidence_ref"}};
  for(var f:fields)p.put(f[0],t.get(f[1]));p.put("dueAt",time(t,"due_at"));p.put("createdAt",time(t,"created_at"));p.put("closedAt",time(t,"closed_at"));
  p.put("safeDisplayAlias",t.get("safe_display_alias")==null?"범위 #"+t.get("resolved_scope_id"):t.get("safe_display_alias"));
  var closure=closureEvidence(t);boolean canClose=closure.values().stream().anyMatch(v->!((List<?>)v).isEmpty());
  boolean open=t.get("status").equals("OPEN");boolean security=access.hasConnectionRole(actor,number(t,"connection_id"),SecretRole.SECURITY);
  p.put("capabilities",Map.of("canAssign",open,"canAddEvidence",open,"canClose",open&&canClose,"canReviewEvidence",open&&security&&Set.of("OWNER_UNKNOWN","EVIDENCE_INCOMPLETE").contains(t.get("missing_reason_code"))));
  p.put("taskGuidance",com.logssey.secret.query.SecretTaskGuidance.build((String)t.get("missing_reason_code"),canClose?"CLOSE_INVESTIGATION":t.get("assignee_user_id")==null?"ASSIGN_INVESTIGATION":"ADD_INVESTIGATION_EVIDENCE",
    Map.of("type","INVESTIGATION","id",t.get("task_id")),open,open?null:"TASK_CLOSED","SECURITY",time(t,"created_at"),time(t,"created_at"),number(t,"task_id"),List.of(),List.of()));
  if(detail){p.put("eligibleAssignees",eligibleOwners(t));p.put("eligibleClosureEvidence",closure);
   p.put("allowedAssignmentReasonCodes",(Boolean.TRUE.equals(t.get("human_follow_up_required"))||"HUMAN_MORE_INFO".equals(t.get("creation_source")))?List.of("INITIAL_ASSIGNMENT","OWNERSHIP_CHANGE","DUE_DATE_CHANGE"):ASSIGNMENT_REASONS);
   p.put("allowedEvidenceKinds",EVIDENCE_KINDS);p.put("activities",jdbc.query("""
    SELECT h.history_id,h.event_type,u.display_name,h.evidence_ref,h.task_version,h.created_at,h.safe_changes::text
    FROM secret_investigation_history h LEFT JOIN dashboard_users u ON u.user_id=h.actor_user_id WHERE h.task_id=? ORDER BY h.history_id DESC
    """,(rs,n)->{Map<String,Object> item=new LinkedHashMap<>();item.put("historyId",rs.getLong(1));item.put("eventType",rs.getString(2));item.put("actorDisplayName",rs.getString(3));item.put("evidenceRef",rs.getString(4));item.put("version",rs.getLong(5));item.put("createdAt",rs.getObject(6,OffsetDateTime.class));item.put("safeChanges",tools.jackson.databind.json.JsonMapper.builder().build().readTree(rs.getString(7)));return item;},t.get("task_id")));
  }return p;
 }
 private void historyChanges(long task,String event,Long actor,long version,String ref,Map<String,Object> changes){jdbc.update("""
  INSERT INTO secret_investigation_history(task_id,event_type,actor_user_id,safe_changes,evidence_ref,task_version)
  VALUES(?,?,?,?::jsonb,?,?)
  """,task,event,actor,tools.jackson.databind.json.JsonMapper.builder().build().writeValueAsString(changes),ref,version);}
 private void history(long task,String event,Long actor,long version,String ref,String key,String safeValue){jdbc.update("""
  INSERT INTO secret_investigation_history(task_id,event_type,actor_user_id,safe_changes,evidence_ref,task_version)
  VALUES(?,?,?,jsonb_build_object(?::text,?::text),?,?)
  """,task,event,actor,key,safeValue,ref,version);}
}
