package com.logssey.secret.query;

import java.util.*;
import static com.logssey.secret.snapshot.SecretReadSnapshots.facts;

/** Navigation and blockers are controlled facts, never free-form AI instructions. */
public final class SecretTaskGuidance {
 private SecretTaskGuidance(){}
 public static Map<String,Object> build(String why,String next,Map<String,Object> target,boolean executable,
   String blocked,String role,Object observed,Object waiting,Long task,List<String> remaining,List<String> priorities){
  return facts("whyHereCode",why,"nextActionCode",next,"target",target,"canExecute",executable,
   "blockedReasonCode",executable?null:blocked,"requiredRole",executable?null:role,"evidenceObservedAt",observed,
   "waitingSince",waiting,"relatedTaskId",task,"remainingReasonCodes",remaining,"priorityReasonCodes",priorities);
 }
 public static Map<String,Object> scope(long id,long connection,List<String> reasons,boolean canPropose,boolean canApprove,Object requestedAt){
  String next=reasons.contains("PENDING_REVIEW")?"REVIEW_SCOPE_CHANGE":reasons.stream().anyMatch(r->r.equals("SOURCE_UNCLASSIFIED")||r.equals("CLASSIFICATION_EVIDENCE_REQUIRED"))?"SET_SCOPE_ORIGIN":"CONFIGURE_STORAGE_POLICY";
  boolean execute=next.equals("REVIEW_SCOPE_CHANGE")?canApprove:canPropose;
  return build(reasons.isEmpty()?"SCOPE_CONFIGURED":reasons.getFirst(),next,facts("type","SCOPE","id",id,"connectionId",connection),execute,
   reasons.contains("PENDING_REVIEW")?"INDEPENDENT_REVIEW_REQUIRED":"ROLE_REQUIRED","SECURITY",null,requestedAt,null,reasons,List.of());
 }
 public static Map<String,Object> location(Map<String,Object> item){
  var capabilities=(Map<?,?>)item.getOrDefault("capabilities",Map.of());
  String next=(String)item.get("nextActionCode");
  boolean execute=!Set.of("REVIEW_EVIDENCE","LINK_CASE","OPEN_REVIEW").contains(next)||Boolean.TRUE.equals(capabilities.get("canReview"));
  List<String> priority=new ArrayList<>();
  if("ABNORMAL".equals(item.get("exposure")))priority.add("CONFIRMED_EXPOSURE");
  if("UNKNOWN".equals(item.get("presence")))priority.add("COVERAGE_BLOCKED");
  if(Boolean.TRUE.equals(item.get("requiresReassessment")))priority.add("EVIDENCE_REQUIRED");
  return build((String)item.get("whyHereCode"),next,facts("type","OCCURRENCE","id",item.get("occurrenceId"),"secretId",item.get("credentialSetId"),"caseId",item.get("caseId")),execute,
    "ROLE_REQUIRED","SECURITY",item.get("lastSeenAt"),null,null,List.of(),List.copyOf(priority));
 }
}
