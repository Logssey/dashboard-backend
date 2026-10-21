package com.logssey.secret.query;

import java.time.*;
import java.util.*;
import static com.logssey.secret.snapshot.SecretReadSnapshots.facts;

/** Counts only the caller's visible, current facts. Missing requires comparable post-action evidence. */
public final class SecretRemediationSummary {
 private SecretRemediationSummary(){}
 public static Map<String,Object> summarize(List<Map<String,Object>> locations,boolean restricted){
  long present=0,missing=0,unknown=0,redetected=0,approved=0,metadata=0,resolved=0;
  for(var item:locations){
   if(Boolean.TRUE.equals(item.get("metadataOnly"))){metadata++;continue;}
   if(Boolean.TRUE.equals(item.get("approvedStorage")))approved++;
   if("RESOLVED".equals(item.get("actionStatus")))resolved++;
   if(!Boolean.TRUE.equals(item.get("requiredRemediation")))continue;
   switch(state(item)){case "PRESENT"->present++;case "MISSING"->missing++;default->unknown++;}
   if(redetected(item))redetected++;
  }
  return facts("unit","Occurrence","comparisonScope","AUTHORIZED_CURRENT_ORIGIN","requiredLocationCount",present+missing+unknown,
    "presentLocationCount",present,"postActionMissingLocationCount",missing,"unknownLocationCount",unknown,
    "postActionRedetectedCount",redetected,"approvedStorageLocationCount",approved,"metadataLocationCount",metadata,
    "resolvedLocationCount",resolved,"visibleLocationCount",locations.size(),"restrictedCoverage",restricted,
    "evidenceObservedAt",locations.stream().flatMap(item->java.util.stream.Stream.of(time(item.get("lastSeenAt")),time(item.get("lastCheckedAt"))))
        .filter(Objects::nonNull).max(Comparator.naturalOrder()).orElse(null),"riskReductionPercent",null);
 }
 public static String state(Map<String,Object> item){
  var check=(Map<?,?>)item.getOrDefault("locationAbsenceCheck",Map.of());
  if("PASSED".equals(check.get("status")))return "MISSING";
  return Boolean.TRUE.equals(item.get("currentCoverage"))&&"PRESENT".equals(item.get("presence"))?"PRESENT":"UNKNOWN";
 }
 public static boolean redetected(Map<String,Object> item){
  var action=time(item.get("lastMaterialActionAt"));var seen=time(item.get("lastSeenAt"));
  return "PRESENT".equals(state(item))&&action!=null&&seen!=null&&seen.isAfter(action);
 }
 public static OffsetDateTime time(Object value){
  if(value instanceof OffsetDateTime time)return time;
  if(value instanceof java.sql.Timestamp time)return time.toInstant().atOffset(ZoneOffset.UTC);
  if(value instanceof String text)try{return OffsetDateTime.parse(text);}catch(java.time.format.DateTimeParseException ignored){}
  return null;
 }
 public static int priority(Map<String,Object> item){
  var guidance=(Map<?,?>)item.getOrDefault("taskGuidance",Map.of());
  var reasons=(List<?>)guidance.getOrDefault("priorityReasonCodes",null);
  if(reasons==null)return 9;
  for(int i=0;i<ORDER.size();i++)if(reasons.contains(ORDER.get(i)))return i;
  return ORDER.size();
 }
 public static final List<String> ORDER=List.of("POST_ACTION_REDETECTED","CONFIRMED_EXPOSURE","VALID_AND_POLICY_DENIED","ASSIGNEE_REQUIRED","FOLLOWUP_OVERDUE","REVALIDATION_REQUIRED","COVERAGE_BLOCKED","EVIDENCE_REQUIRED");
}
