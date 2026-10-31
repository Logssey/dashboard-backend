package com.logssey.secret.response;
import java.util.*;
import com.logssey.secret.access.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import static com.logssey.secret.snapshot.SecretReadSnapshots.facts;
/** A read projection using the same current facts that the command locks and rechecks. */
@Service
public class SecretLocationReadiness {
 private final JdbcTemplate jdbc; private final SecretAccessService access;
 public SecretLocationReadiness(JdbcTemplate jdbc,SecretAccessService access){this.jdbc=jdbc;this.access=access;}
 public Map<String,Object> capabilities(SecretPrincipal actor,long caseId,long occurrence){
  var rows=jdbc.queryForList("""
   SELECT c.is_current,c.disposition,c.action_status,c.case_origin,co.response_status,co.action_cycle,
    co.actions_completed_at,co.last_material_action_at,co.assigned_user_id,co.assigned_team,
    o.connection_id,o.presence_status,o.last_seen_at,(k.fingerprint=v.baseline_identity AND k.fingerprint_key_version=v.baseline_fingerprint_version) AS same_identity,k.component_state,k.fingerprint_key_version,cn.provider,cn.status AS connection_status,
    s.enabled,s.content_type,s.history_limit,s.approved_ref,s.response_origin,s.revision,s.response_origin_version,v.scope_origin_version AS revalidation_origin_version,
    v.scope_revision AS revalidation_revision,v.occurrence_version AS revalidation_occurrence_version,co.version AS location_version,
    EXISTS(SELECT 1 FROM secret_jobs j WHERE j.connection_id=o.connection_id AND j.kind IN ('FULL_SCAN','REVALIDATE') AND j.status IN ('PENDING','LEASED')) AS busy,
    v.revalidation_id,v.status AS revalidation_status,v.action_cycle AS revalidation_cycle,
    v.last_material_action_at AS revalidation_action_at,v.actions_completed_at AS revalidation_completed_at,v.finished_at AS revalidation_finished_at,
    vr.scope_version AS revalidation_connection_version,cn.scope_version,
    EXISTS(SELECT 1 FROM secret_scope_outcomes outcome WHERE outcome.scope_id=o.scope_id AND outcome.scope_revision=s.revision
     AND outcome.requested_at>v.requested_at AND outcome.scope_outcome IN ('PARTIAL','FAILED','SKIPPED','UNKNOWN')) AS later_incomplete
   FROM secret_case_occurrences co JOIN secret_response_cases c USING(case_id)
   JOIN secret_occurrences o USING(occurrence_id) JOIN secret_credential_sets k ON k.credential_set_id=c.credential_set_id
   JOIN secret_connections cn ON cn.connection_id=o.connection_id JOIN secret_connection_scopes s USING(scope_id)
   LEFT JOIN LATERAL(SELECT * FROM secret_case_revalidations WHERE case_id=co.case_id AND occurrence_id=co.occurrence_id
    ORDER BY requested_at DESC,revalidation_id DESC LIMIT 1)v ON true LEFT JOIN secret_scan_runs vr ON vr.run_id=v.run_id WHERE co.case_id=? AND co.occurrence_id=?
   """,caseId,occurrence);
  if(rows.isEmpty())return facts("canRequestRevalidation",false,"canResume",false,"revalidationBlockReasonCode","NO_CURRENT_CASE");
  var o=rows.getFirst();boolean assigned=access.hasConnectionRole(actor,((Number)o.get("connection_id")).longValue(),SecretRole.REMEDIATOR)
   &&(Objects.equals(o.get("assigned_user_id"),actor.userId())||(o.get("assigned_user_id")==null&&o.get("assigned_team")!=null
    &&Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM secret_team_memberships WHERE user_id=? AND team_name=? AND removed_at IS NULL)",Boolean.class,actor.userId(),o.get("assigned_team")))));
  String reason=null;
  if(!assigned)reason="LOCATION_ASSIGNEE_REQUIRED";
  else if(!Boolean.TRUE.equals(o.get("is_current"))||!"IN_SCOPE".equals(o.get("disposition"))||"RESOLVED".equals(o.get("action_status")))reason="CASE_NOT_ACTIVE";
  else if(!"REVALIDATION_PENDING".equals(o.get("response_status"))||o.get("actions_completed_at")==null||o.get("last_material_action_at")==null)reason="COMPLETE_ACTIONS_REQUIRED";
  else if(!"CONFIRMED".equals(o.get("component_state"))||o.get("fingerprint_key_version")==null)reason="COMPLETE_IDENTITY_REQUIRED";
  else if(!"GITHUB".equals(o.get("provider"))||!SecretGithubScopePolicy.approved((String)o.get("content_type"),(String)o.get("history_limit"),(String)o.get("approved_ref")))reason="SOURCE_REVALIDATION_UNSUPPORTED";
  else if(!Boolean.TRUE.equals(o.get("enabled"))||!"ACTIVE".equals(o.get("connection_status"))||!Objects.equals(o.get("case_origin"),o.get("response_origin")))reason="SCOPE_UNAVAILABLE";
  else if(Boolean.TRUE.equals(o.get("busy")))reason="ACTIVE_JOB_EXISTS";
  boolean canResume=assigned&&Boolean.TRUE.equals(o.get("is_current"))&&"IN_SCOPE".equals(o.get("disposition"))
   &&"REVALIDATION_PENDING".equals(o.get("response_status"))&&"PRESENT".equals(o.get("revalidation_status"))
   &&Objects.equals(o.get("action_cycle"),o.get("revalidation_cycle"))&&Objects.equals(o.get("case_origin"),o.get("response_origin"))&&o.get("last_material_action_at")!=null
   &&Objects.equals(o.get("last_material_action_at"),o.get("revalidation_action_at"))&&!Boolean.TRUE.equals(o.get("busy"));
  boolean missing="MISSING".equals(o.get("revalidation_status"))&&"MISSING".equals(o.get("presence_status"))
   &&Boolean.TRUE.equals(o.get("is_current"))&&Boolean.TRUE.equals(o.get("same_identity"))&&"IN_SCOPE".equals(o.get("disposition"))&&"REVALIDATION_PENDING".equals(o.get("response_status"))
   &&Objects.equals(o.get("scope_version"),o.get("revalidation_connection_version"))&&!Boolean.TRUE.equals(o.get("later_incomplete"))
   &&Objects.equals(o.get("actions_completed_at"),o.get("revalidation_completed_at"))&&Objects.equals(o.get("action_cycle"),o.get("revalidation_cycle"))
   &&Objects.equals(o.get("revision"),o.get("revalidation_revision"))&&Objects.equals(o.get("response_origin_version"),o.get("revalidation_origin_version"))&&Objects.equals(o.get("location_version"),o.get("revalidation_occurrence_version"))
   &&o.get("last_material_action_at")!=null&&Objects.equals(o.get("last_material_action_at"),o.get("revalidation_action_at"))
   &&Boolean.TRUE.equals(o.get("enabled"))&&"ACTIVE".equals(o.get("connection_status"));
  return facts("locationAbsenceCheck",facts("status",missing?"PASSED":"UNKNOWN","reasonCode",missing?"COMPARABLE_POST_ACTION_MISSING":"POST_ACTION_EVIDENCE_REQUIRED"),
   "canRequestRevalidation",reason==null,"canResume",canResume,"revalidationBlockReasonCode",reason,
   "recentRevalidation",jdbc.queryForList("""
     SELECT v.revalidation_id AS "revalidationId",v.occurrence_id AS "occurrenceId",v.run_id AS "runId",j.status AS "jobStatus",
       v.status AS result,v.failure_code AS "failureCode",v.requested_at AS "requestedAt",v.finished_at AS "finishedAt",?::boolean AS "canViewRun"
     FROM secret_case_revalidations v JOIN secret_jobs j USING(job_id) WHERE v.revalidation_id=?
     """,access.canReadConnectionFacts(actor,((Number)o.get("connection_id")).longValue()),o.get("revalidation_id")).stream().findFirst().orElse(null));
 }
}
