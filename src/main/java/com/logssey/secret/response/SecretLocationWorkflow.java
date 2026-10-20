package com.logssey.secret.response;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.OffsetDateTime;
import java.util.*;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.access.*;
import com.logssey.secret.command.*;
import com.logssey.secret.snapshot.SecretReadSnapshots;
import static com.logssey.secret.snapshot.SecretReadSnapshots.facts;
import static com.logssey.secret.command.SecretCommandExecutor.requireExpectedVersion;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Current location facts and commands. A coordinator never inherits location action rights. */
@Service
public class SecretLocationWorkflow {
    private static final Set<String> REASONS=Set.of("INITIAL_ASSIGNMENT","OWNERSHIP_CHANGE","TEAM_TRANSFER","UNASSIGNED","OTHER");
    private static final Set<String> ACTIONS=Set.of("ROTATED","REVOKED","REMOVED_FROM_SOURCE","PERMISSION_REDUCED");
    private final JdbcTemplate jdbc;
    private final NamedParameterJdbcTemplate named;
    private final SecretAccessService access;
    private final SecretCommandExecutor commands;
    private final SecretReadSnapshots snapshots;
    public SecretLocationWorkflow(JdbcTemplate jdbc,SecretAccessService access,SecretCommandExecutor commands,SecretReadSnapshots snapshots) {
        this.jdbc=jdbc;this.named=new NamedParameterJdbcTemplate(jdbc);this.access=access;this.commands=commands;this.snapshots=snapshots;
    }
    public record Assignment(String team,Long assigneeUserId,String reasonCode,Long expectedCaseVersion,Long expectedOccurrenceVersion) {}
    public record Action(String actionType,Long occurrenceId,OffsetDateTime performedAt,String evidenceRef,
                         Long expectedCaseVersion,Long expectedOccurrenceVersion,String idempotencyKey) {}
    public record Completion(Long expectedCaseVersion,Long expectedOccurrenceVersion,String idempotencyKey) {}
    public record Checklist(Boolean completed,String guideVersion,String evidenceRef,Long expectedCaseVersion) {}
    public record Coordinator(String team,Long assigneeUserId,String reasonCode,Long expectedVersion) {}

    @Transactional(readOnly=true)
    public Map<String,Object> detail(long caseId,String login) {
        SecretPrincipal actor=access.requirePrincipal(login);
        List<Map<String,Object>> locations=visibleLocations(caseId,actor);
        if(locations.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);
        var c=jdbc.queryForMap("""
            SELECT c.*,k.masked_label,k.issuer,k.credential_type,u.display_name AS assignee_name,
                (to_jsonb(c)->>'opening_decision_id')::bigint AS opening_decision
            FROM secret_response_cases c JOIN secret_credential_sets k USING(credential_set_id)
            LEFT JOIN dashboard_users u ON u.user_id=c.assigned_user_id WHERE case_id=?
            """,caseId);
        boolean allSecurity=hasAllSecurity(actor,caseId);
        boolean current=Boolean.TRUE.equals(c.get("is_current"))&&"IN_SCOPE".equals(c.get("disposition"));
        List<Map<String,Object>> items=locations.stream().map(o->{
            long occurrence=num(o,"occurrence_id"),connection=num(o,"connection_id");
            boolean security=access.hasConnectionRole(actor,connection,SecretRole.SECURITY);
            boolean assigned=assignedRemediator(actor,caseId,occurrence);
            boolean actionable=current&&Set.of("OPEN","IN_PROGRESS").contains(o.get("response_status"));
            return facts("occurrenceId",occurrence,"safeLocationLabel","위치 #"+occurrence,
                "source",o.get("source"),"environment",o.get("environment"),"exposure",o.get("exposure_status"),
                "presence",o.get("presence_status"),"responseStatus",o.get("response_status"),"version",o.get("version"),
                "assignedTeam",o.get("assigned_team"),"assignedUserId",o.get("assigned_user_id"),
                "assigneeDisplayName",o.get("assignee_name"),"actionCycle",o.get("action_cycle"),
                "lastMaterialActionAt",o.get("last_material_action_at"),"actionsCompletedAt",o.get("actions_completed_at"),
                "canAssign",security&&current,"canRecordAction",assigned&&actionable,"canCompleteActions",assigned&&actionable&&o.get("last_material_action_at")!=null,
                "canRequestRevalidation",false,"canResume",false);
        }).toList();
        return facts("caseId",caseId,"secretId",c.get("credential_set_id"),"maskedLabel",c.get("masked_label"),
            "issuer",c.get("issuer"),"credentialType",c.get("credential_type"),"caseOrigin",c.get("case_origin"),
            "stage",c.get("action_status"),"disposition",c.get("disposition"),"isCurrent",c.get("is_current"),
            "assigneeTeam",allSecurity?c.get("assigned_team"):null,"assigneeUserId",allSecurity?c.get("assigned_user_id"):null,
            "assigneeDisplayName",allSecurity?c.get("assignee_name"):null,"version",c.get("version"),
            "openingDecisionId",c.get("opening_decision"),"createdAt",c.get("opened_at"),"updatedAt",allSecurity?c.get("updated_at"):null,
            "visibleOccurrenceCount",items.size(),"restrictedCoverage",!access.hasGlobalRole(actor,SecretRole.SECURITY),"occurrences",items,
            "checklist",checklist(caseId,locations),"actions",List.of(),"assignmentHistory",List.of(),
            "checklistHistory",List.of(),"stageHistory",List.of(),"reviews",List.of(),
            "reviewStatus","NOT_REQUIRED","readAt",OffsetDateTime.now(),"changedSinceSnapshot",false,
            "capabilities",facts("canAssign",allSecurity&&current,"canReview",false,"canStart",false,
                "canRecordAction",items.stream().anyMatch(i->Boolean.TRUE.equals(i.get("canRecordAction"))),
                "canUpdateChecklist",current&&(allSecurity||items.stream().anyMatch(i->Boolean.TRUE.equals(i.get("canRecordAction")))),"canResolve",false,"canRequestRevalidation",false));
    }

    @Transactional(readOnly=true)
    public Map<String,Object> list(String login,String origin,String scope,String stages,String assignmentStatus,String assignee,int page,int size) {
        SecretPrincipal actor=access.requirePrincipal(login);access.requireAnyRole(actor);page(page,size);
        if(!Set.of("PRODUCTION","TEST").contains(origin)||!Set.of("currentCases","history").contains(scope))invalid();
        Set<String> stageSet=csv(stages,Set.of("OPEN","IN_PROGRESS","REVALIDATION_PENDING","RESOLVED"));
        if(assignmentStatus!=null&&!Set.of("UNASSIGNED","TEAM_ONLY","PERSONAL").contains(assignmentStatus))invalid();
        if(assignee!=null&&!assignee.matches("ME|UNASSIGNED|[1-9][0-9]{0,17}"))invalid();
        var all=jdbc.queryForList("""
            SELECT c.case_id,c.case_origin,c.credential_set_id,c.action_status,c.assigned_team,c.assigned_user_id,c.version,
                   c.opened_at,c.updated_at,k.masked_label,k.issuer,k.credential_type
            FROM secret_response_cases c JOIN secret_credential_sets k USING(credential_set_id)
            WHERE c.case_origin=? AND c.is_current=? ORDER BY c.updated_at DESC,c.case_id DESC
            """,origin,"currentCases".equals(scope));
        var visible=new ArrayList<Map<String,Object>>();
        for(var c:all) {
            long id=num(c,"case_id");var loc=visibleLocations(id,actor);if(loc.isEmpty())continue;
            if(!stageSet.isEmpty()&&!stageSet.contains(c.get("action_status")))continue;
            boolean full=hasAllSecurity(actor,id);
            boolean matched=loc.stream().anyMatch(o->assignmentMatches(o,assignmentStatus,assignee,actor.userId()));
            if(!matched)continue;
            visible.add(facts("caseId",id,"secretId",c.get("credential_set_id"),"maskedLabel",c.get("masked_label"),
                "issuer",c.get("issuer"),"credentialType",c.get("credential_type"),"caseOrigin",c.get("case_origin"),
                "stage",c.get("action_status"),"version",c.get("version"),"assigneeTeam",full?c.get("assigned_team"):null,
                "assigneeUserId",full?c.get("assigned_user_id"):null,"createdAt",c.get("opened_at"),
                "updatedAt",full?c.get("updated_at"):null,"visibleOccurrenceCount",loc.size(),"restrictedCoverage",!full));
        }
        return facts("items",visible.stream().skip((long)page*size).limit(size).toList(),"total",visible.size(),"page",page,"size",size,
            "scope",scope,"unit","ResponseCase","asOf",OffsetDateTime.now());
    }

    @Transactional(readOnly=true)
    public Map<String,Object> activities(long caseId,String login,int page,int size) {
        SecretPrincipal actor=access.requirePrincipal(login);page(page,size);var loc=visibleLocations(caseId,actor);
        if(loc.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);
        var ids=loc.stream().map(o->num(o,"occurrence_id")).toList();
        var args=new HashMap<String,Object>();args.put("case",caseId);args.put("ids",ids);args.put("full",hasAllSecurity(actor,caseId));
        String from=" FROM secret_location_activities a LEFT JOIN secret_action_records r ON a.activity_type='ACTION_RECORDED' AND r.action_id=a.reference_id AND r.case_id=a.case_id AND r.occurrence_id=a.occurrence_id WHERE a.case_id=:case AND (a.occurrence_id IN (:ids) OR (a.occurrence_id IS NULL AND :full))";
        long total=named.queryForObject("SELECT count(*)"+from,args,Long.class);
        args.put("limit",size);args.put("offset",(long)page*size);
        var items=named.query("SELECT a.*,r.action_type,r.performed_at,r.evidence_ref"+from+" ORDER BY happened_at DESC,activity_id DESC LIMIT :limit OFFSET :offset",args,
            (rs,n)->facts("activityId",rs.getLong("activity_id"),"occurrenceId",rs.getObject("occurrence_id",Long.class),
                "type",rs.getString("activity_type"),"actorUserId",rs.getLong("actor_user_id"),"referenceId",rs.getObject("reference_id",Long.class),
                "reasonCode",rs.getString("reason_code"),"happenedAt",rs.getObject("happened_at",OffsetDateTime.class),
                "actionType",rs.getString("action_type"),"performedAt",rs.getObject("performed_at",OffsetDateTime.class),"evidenceRef",rs.getString("evidence_ref")));
        return facts("items",items,"total",total,"page",page,"size",size,"historyComplete",false,"reasonCode","LEGACY_ACTIVITIES_SEPARATE");
    }

    @Transactional(readOnly=true)
    public Map<String,Object> assignees(long caseId,Long occurrenceId,String login) {
        SecretPrincipal actor=access.requirePrincipal(login);
        if(occurrenceId==null) {if(!hasAllSecurity(actor,caseId))throw new ApiException(ErrorCode.FORBIDDEN);}
        else requireSecurity(actor,caseId,occurrenceId);
        var rows=jdbc.queryForList("""
            SELECT u.user_id,u.display_name,m.team_name FROM dashboard_users u
            LEFT JOIN secret_team_memberships m ON m.user_id=u.user_id AND m.removed_at IS NULL
            WHERE EXISTS(SELECT 1 FROM secret_role_grants g WHERE g.user_id=u.user_id AND g.role='REMEDIATOR' AND g.revoked_at IS NULL)
              AND NOT EXISTS(SELECT 1 FROM secret_case_occurrences co JOIN secret_occurrences o USING(occurrence_id)
                WHERE co.case_id=? AND (CAST(? AS bigint) IS NULL OR co.occurrence_id=?) AND NOT EXISTS(
                  SELECT 1 FROM secret_role_grants g WHERE g.user_id=u.user_id AND g.role='REMEDIATOR' AND g.revoked_at IS NULL
                    AND (g.connection_id IS NULL OR g.connection_id=o.connection_id)))
            ORDER BY u.display_name,u.user_id,m.team_name
            """,caseId,occurrenceId,occurrenceId);
        return facts("items",rows.stream().map(r->facts("userId",r.get("user_id"),"displayName",r.get("display_name"),"team",r.get("team_name"))).toList());
    }

    @Transactional
    public Map<String,Object> assign(long caseId,long occurrenceId,Assignment request,String login) {
        SecretPrincipal actor=access.requirePrincipal(login);requireSecurity(actor,caseId,occurrenceId);
        if(request==null||!REASONS.contains(request.reasonCode()==null?"":request.reasonCode())
            ||(request.team()!=null&&!request.team().matches("[A-Za-z0-9가-힣][A-Za-z0-9가-힣 _-]{0,99}")))invalid();
        var c=lockCase(caseId);var o=lockLocation(caseId,occurrenceId);
        versions(request.expectedCaseVersion(),request.expectedOccurrenceVersion(),c,o);active(c);
        if(request.assigneeUserId()!=null) {
            var candidate=new SecretPrincipal(request.assigneeUserId());
            if(!access.hasConnectionRole(candidate,num(o,"connection_id"),SecretRole.REMEDIATOR))invalid();
            if(request.team()!=null&&!member(candidate.userId(),request.team()))invalid();
        } else if(request.team()!=null&&!eligibleTeam(num(o,"connection_id"),request.team()))invalid();
        jdbc.update("UPDATE secret_case_occurrences SET assigned_team=?,assigned_user_id=?,version=version+1 WHERE case_id=? AND occurrence_id=?",
            request.team(),request.assigneeUserId(),caseId,occurrenceId);
        bumpCase(caseId,null);event(caseId,occurrenceId,"LOCATION_ASSIGNED",actor.userId(),num(c,"version")+1,num(o,"version")+1,null,request.reasonCode());
        jdbc.update("INSERT INTO secret_audit_events(case_id,event_type,actor_user_id,case_version) VALUES (?,'LOCATION_ASSIGNED',?,?)",caseId,actor.userId(),num(c,"version")+1);
        snapshots.invalidateOccurrence(occurrenceId);return detail(caseId,login);
    }

    @Transactional
    public Map<String,Object> coordinator(long caseId,Coordinator request,String login) {
        var actor=access.requirePrincipal(login);if(!hasAllSecurity(actor,caseId))throw new ApiException(ErrorCode.FORBIDDEN);
        if(request==null||!REASONS.contains(request.reasonCode()==null?"":request.reasonCode())
            ||(request.team()!=null&&!request.team().matches("[A-Za-z0-9가-힣][A-Za-z0-9가-힣 _-]{0,99}")))invalid();
        var c=lockCase(caseId);requireExpectedVersion(request.expectedVersion(),num(c,"version"));active(c);
        var candidates=(List<?>)assignees(caseId,null,login).get("items");
        if(request.assigneeUserId()!=null&&candidates.stream().noneMatch(v->Objects.equals(((Map<?,?>)v).get("userId"),request.assigneeUserId())
            &&(request.team()==null||Objects.equals(((Map<?,?>)v).get("team"),request.team()))))invalid();
        if(request.assigneeUserId()==null&&request.team()!=null&&candidates.stream().noneMatch(v->Objects.equals(((Map<?,?>)v).get("team"),request.team())))invalid();
        jdbc.update("UPDATE secret_response_cases SET assigned_team=?,assigned_user_id=?,version=version+1,updated_at=now() WHERE case_id=?",request.team(),request.assigneeUserId(),caseId);
        jdbc.update("INSERT INTO secret_assignment_history(case_id,from_team,to_team,from_user_id,to_user_id,reason,changed_by_user_id,case_version) VALUES (?,?,?,?,?,?,?,?)",
            caseId,c.get("assigned_team"),request.team(),c.get("assigned_user_id"),request.assigneeUserId(),request.reasonCode(),actor.userId(),num(c,"version")+1);
        event(caseId,null,"COORDINATOR_ASSIGNED",actor.userId(),num(c,"version")+1,null,null,request.reasonCode());
        jdbc.update("INSERT INTO secret_audit_events(case_id,event_type,actor_user_id,case_version) VALUES (?,'ASSIGNMENT_CHANGED',?,?)",caseId,actor.userId(),num(c,"version")+1);
        visibleLocations(caseId,actor).forEach(o->snapshots.invalidateOccurrence(num(o,"occurrence_id")));
        return detail(caseId,login);
    }

    public SecretCommandResult action(long caseId,Action request,String login) {
        SecretPrincipal actor=access.requirePrincipal(login);
        if(request==null||request.occurrenceId()==null||!ACTIONS.contains(request.actionType()==null?"":request.actionType())
            ||request.performedAt()==null||!evidence(request.evidenceRef()))invalid();
        long occurrence=request.occurrenceId();
        return commands.execute(actor,SecretCommandExecutor.Kind.LOCATION_ACTION,request.idempotencyKey(),digest(caseId,request),
            ()->requireAssigned(actor,caseId,occurrence),()->{
                var c=lockCase(caseId);var o=lockLocation(caseId,occurrence);versions(request.expectedCaseVersion(),request.expectedOccurrenceVersion(),c,o);active(c);
                OffsetDateTime now=jdbc.queryForObject("SELECT CURRENT_TIMESTAMP",OffsetDateTime.class);
                if(request.performedAt().isBefore(now.minusDays(30))||request.performedAt().isAfter(now.plusMinutes(5)))invalid();
                if(!Set.of("OPEN","IN_PROGRESS").contains(o.get("response_status")))conflict();
                long id=jdbc.queryForObject("""
                    INSERT INTO secret_action_records(case_id,occurrence_id,action_type,performed_at,recorded_by_user_id,evidence_ref,case_version,action_cycle)
                    VALUES (?,?,?,?,?,?,?,?) RETURNING action_id
                    """,Long.class,caseId,occurrence,request.actionType(),request.performedAt(),actor.userId(),request.evidenceRef(),num(c,"version")+1,num(o,"action_cycle"));
                jdbc.update("""
                    UPDATE secret_case_occurrences SET response_status='IN_PROGRESS',version=version+1,
                      last_material_action_at=CASE WHEN ? THEN greatest(last_material_action_at,?) ELSE last_material_action_at END
                    WHERE case_id=? AND occurrence_id=?
                    """,!"PERMISSION_REDUCED".equals(request.actionType()),request.performedAt(),caseId,occurrence);
                bumpCase(caseId,"IN_PROGRESS");stage(c,"IN_PROGRESS",actor.userId());event(caseId,occurrence,"ACTION_RECORDED",actor.userId(),num(c,"version")+1,num(o,"version")+1,id,request.actionType());
                snapshots.invalidateOccurrence(occurrence);return new SecretCommandResult(caseId,num(c,"version")+1,SecretCommandResult.Status.IN_PROGRESS);
            });
    }
    public SecretCommandResult complete(long caseId,long occurrence,Completion request,String login) {
        SecretPrincipal actor=access.requirePrincipal(login);if(request==null)invalid();
        return commands.execute(actor,SecretCommandExecutor.Kind.COMPLETE_LOCATION_ACTIONS,request.idempotencyKey(),digest(caseId,occurrence,request),
            ()->requireAssigned(actor,caseId,occurrence),()->{
                var c=lockCase(caseId);var o=lockLocation(caseId,occurrence);versions(request.expectedCaseVersion(),request.expectedOccurrenceVersion(),c,o);active(c);
                if(!"IN_PROGRESS".equals(o.get("response_status"))||o.get("last_material_action_at")==null)conflict();
                boolean material=Boolean.TRUE.equals(jdbc.queryForObject("""
                    SELECT EXISTS(SELECT 1 FROM secret_action_records WHERE case_id=? AND occurrence_id=? AND action_cycle=?
                      AND action_type IN ('ROTATED','REVOKED','REMOVED_FROM_SOURCE'))
                    """,Boolean.class,caseId,occurrence,num(o,"action_cycle")));
                if(!material)conflict();
                jdbc.update("UPDATE secret_case_occurrences SET response_status='REVALIDATION_PENDING',actions_completed_at=now(),version=version+1 WHERE case_id=? AND occurrence_id=?",caseId,occurrence);
                boolean remaining=Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM secret_case_occurrences WHERE case_id=? AND response_status IN ('OPEN','IN_PROGRESS'))",Boolean.class,caseId));
                String stage=remaining?"IN_PROGRESS":"REVALIDATION_PENDING";bumpCase(caseId,stage);stage(c,stage,actor.userId());
                event(caseId,occurrence,"ACTIONS_COMPLETED",actor.userId(),num(c,"version")+1,num(o,"version")+1,null,null);
                snapshots.invalidateOccurrence(occurrence);return new SecretCommandResult(caseId,num(c,"version")+1,SecretCommandResult.Status.valueOf(stage));
            });
    }
    @Transactional
    public Map<String,Object> checklist(long caseId,long item,Checklist request,String login) {
        SecretPrincipal actor=access.requirePrincipal(login);
        if(request==null||request.completed()==null||!"S2_V1".equals(request.guideVersion())
            ||(request.completed()&&!evidence(request.evidenceRef()))||(!request.completed()&&request.evidenceRef()!=null))invalid();
        var c=lockCase(caseId);requireExpectedVersion(request.expectedCaseVersion(),num(c,"version"));active(c);
        var before=jdbc.queryForList("SELECT * FROM secret_checklist_items WHERE case_id=? AND item_id=? FOR UPDATE",caseId,item);
        if(before.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);
        Long occurrence=(Long)before.getFirst().get("occurrence_id");
        if(occurrence==null) {if(!hasAllSecurity(actor,caseId))throw new ApiException(ErrorCode.FORBIDDEN);}
        else if(!assignedRemediator(actor,caseId,occurrence))requireSecurity(actor,caseId,occurrence);
        String status=request.completed()?"DONE":"TODO";
        jdbc.update("""
            UPDATE secret_checklist_items SET status=?,evidence_ref=?,completed_at=CASE WHEN ? THEN now() ELSE NULL END,
              completed_by_user_id=CASE WHEN ? THEN ?::bigint ELSE NULL END,updated_at=now() WHERE item_id=?
            """,status,request.evidenceRef(),request.completed(),request.completed(),actor.userId(),item);
        bumpCase(caseId,null);
        jdbc.update("INSERT INTO secret_checklist_history(case_id,item_id,from_status,to_status,evidence_ref,changed_by_user_id,case_version) VALUES (?,?,?,?,?,?,?)",
            caseId,item,before.getFirst().get("status"),status,request.evidenceRef(),actor.userId(),num(c,"version")+1);
        event(caseId,occurrence,"CHECKLIST_CHANGED",actor.userId(),num(c,"version")+1,null,item,status);
        jdbc.update("INSERT INTO secret_audit_events(case_id,event_type,actor_user_id,case_version) VALUES (?,'CHECKLIST_CHANGED',?,?)",caseId,actor.userId(),num(c,"version")+1);
        return detail(caseId,login);
    }

    public void rejectLegacy(long caseId,String login) {detail(caseId,login);conflict();}
    public boolean assignedRemediator(SecretPrincipal actor,long caseId,long occurrence) {
        return Boolean.TRUE.equals(jdbc.queryForObject("""
            SELECT EXISTS(SELECT 1 FROM secret_case_occurrences co JOIN secret_occurrences o USING(occurrence_id)
              JOIN secret_response_cases c USING(case_id) WHERE co.case_id=? AND co.occurrence_id=? AND c.is_current AND
                (co.assigned_user_id=? OR (co.assigned_user_id IS NULL AND EXISTS(SELECT 1 FROM secret_team_memberships m
                  WHERE m.user_id=? AND m.team_name=co.assigned_team AND m.removed_at IS NULL))) AND
                EXISTS(SELECT 1 FROM secret_role_grants g WHERE g.user_id=? AND g.role='REMEDIATOR' AND g.revoked_at IS NULL
                  AND (g.connection_id IS NULL OR g.connection_id=o.connection_id)))
            """,Boolean.class,caseId,occurrence,actor.userId(),actor.userId(),actor.userId()));
    }
    public boolean hasAllSecurity(SecretPrincipal actor,long caseId) {
        return Boolean.TRUE.equals(jdbc.queryForObject("""
            SELECT EXISTS(SELECT 1 FROM secret_case_occurrences WHERE case_id=?) AND NOT EXISTS(
              SELECT 1 FROM secret_case_occurrences co JOIN secret_occurrences o USING(occurrence_id) WHERE co.case_id=? AND NOT EXISTS(
                SELECT 1 FROM secret_role_grants g WHERE g.user_id=? AND g.role='SECURITY' AND g.revoked_at IS NULL
                  AND (g.connection_id IS NULL OR g.connection_id=o.connection_id)))
            """,Boolean.class,caseId,caseId,actor.userId()));
    }
    public Map<String,Object> lockCase(long id) {
        var rows=jdbc.queryForList("SELECT * FROM secret_response_cases WHERE case_id=? FOR UPDATE",id);
        if(rows.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);return rows.getFirst();
    }
    public Map<String,Object> lockLocation(long caseId,long occurrence) {
        var rows=jdbc.queryForList("""
            SELECT co.*,o.connection_id,o.scope_id FROM secret_case_occurrences co JOIN secret_occurrences o USING(occurrence_id)
            WHERE co.case_id=? AND co.occurrence_id=? FOR UPDATE OF co
            """,caseId,occurrence);
        if(rows.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);return rows.getFirst();
    }
    public List<Map<String,Object>> visibleLocations(long caseId,SecretPrincipal actor) {
        return named.queryForList("""
            SELECT co.*,o.connection_id,o.environment,o.exposure_status,o.presence_status,conn.provider AS source,u.display_name AS assignee_name
            FROM secret_case_occurrences co JOIN secret_occurrences o USING(occurrence_id)
            JOIN secret_connections conn ON conn.connection_id=o.connection_id
            LEFT JOIN dashboard_users u ON u.user_id=co.assigned_user_id
            WHERE co.case_id=:case AND
            """+SecretOccurrenceAccessSql.predicate("o",":userId")+" ORDER BY co.occurrence_id",Map.of("case",caseId,"userId",actor.userId()));
    }
    private List<Map<String,Object>> checklist(long caseId,List<Map<String,Object>> locations) {
        return named.queryForList("SELECT item_id,occurrence_id,guide_version,item_code,status,evidence_ref FROM secret_checklist_items WHERE case_id=:case AND occurrence_id IN (:ids) ORDER BY occurrence_id,item_id",
            Map.of("case",caseId,"ids",locations.stream().map(o->num(o,"occurrence_id")).toList()))
            .stream().map(i->facts("itemId",i.get("item_id"),"occurrenceId",i.get("occurrence_id"),"guideVersion",i.get("guide_version"),"code",i.get("item_code"),"status",i.get("status"),"evidenceRef",i.get("evidence_ref"))).toList();
    }
    private void requireAssigned(SecretPrincipal actor,long c,long o) {if(!assignedRemediator(actor,c,o))throw new ApiException(ErrorCode.FORBIDDEN);}
    private void requireSecurity(SecretPrincipal actor,long c,long o) {
        var rows=jdbc.queryForList("SELECT connection_id FROM secret_occurrences WHERE occurrence_id=? AND EXISTS(SELECT 1 FROM secret_case_occurrences WHERE case_id=? AND occurrence_id=?)",o,c,o);
        if(rows.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);access.requireConnectionRole(actor,num(rows.getFirst(),"connection_id"),SecretRole.SECURITY);
    }
    private boolean member(long user,String team) {return Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM secret_team_memberships WHERE user_id=? AND team_name=? AND removed_at IS NULL)",Boolean.class,user,team));}
    private boolean eligibleTeam(long conn,String team) {return Boolean.TRUE.equals(jdbc.queryForObject("""
        SELECT EXISTS(SELECT 1 FROM secret_team_memberships m JOIN secret_role_grants g ON g.user_id=m.user_id
         WHERE m.team_name=? AND m.removed_at IS NULL AND g.role='REMEDIATOR' AND g.revoked_at IS NULL AND (g.connection_id IS NULL OR g.connection_id=?))
        """,Boolean.class,team,conn));}
    private void bumpCase(long c,String stage) {jdbc.update("UPDATE secret_response_cases SET action_status=coalesce(?,action_status),version=version+1,updated_at=now() WHERE case_id=?",stage,c);}
    private void stage(Map<String,Object> before,String after,long actor) {
        if(!Objects.equals(before.get("action_status"),after))jdbc.update("INSERT INTO secret_case_stage_history(case_id,from_status,to_status,reason_code,actor_user_id,case_version) VALUES(?,?,?,'EXTERNAL_ACTION_RECORDED',?,?)",
            num(before,"case_id"),before.get("action_status"),after,actor,num(before,"version")+1);
    }
    private void event(long c,Long o,String type,long actor,long cv,Long ov,Long ref,String reason) {jdbc.update("INSERT INTO secret_location_activities(case_id,occurrence_id,activity_type,actor_user_id,case_version,occurrence_version,reference_id,reason_code) VALUES (?,?,?,?,?,?,?,?)",c,o,type,actor,cv,ov,ref,reason);}
    private static void versions(Long cv,Long ov,Map<String,Object> c,Map<String,Object> o) {requireExpectedVersion(cv,num(c,"version"));requireExpectedVersion(ov,num(o,"version"));}
    private static void active(Map<String,Object> c) {if(!Boolean.TRUE.equals(c.get("is_current"))||!"IN_SCOPE".equals(c.get("disposition"))||"RESOLVED".equals(c.get("action_status")))conflict();}
    private static boolean assignmentMatches(Map<String,Object> o,String status,String who,long actor) {
        Object user=o.get("assigned_user_id"),team=o.get("assigned_team");
        if(status!=null&&!status.equals(user!=null?"PERSONAL":team!=null?"TEAM_ONLY":"UNASSIGNED"))return false;
        return who==null||("UNASSIGNED".equals(who)?user==null&&team==null:Objects.equals(user,"ME".equals(who)?actor:Long.valueOf(who)));
    }
    static long num(Map<String,Object> row,String key) {return ((Number)row.get(key)).longValue();}
    static boolean evidence(String ref) {return ref!=null&&ref.matches("(TICKET|CHANGE):[A-Z]{2,10}-[1-9][0-9]{0,9}");}
    private static byte[] digest(Object... parts) {try{return MessageDigest.getInstance("SHA-256").digest(Arrays.deepToString(parts).getBytes(StandardCharsets.UTF_8));}catch(Exception e){throw new IllegalStateException(e);}}
    private static Set<String> csv(String input,Set<String> allowed) {if(input==null||input.isBlank())return Set.of();var result=new HashSet<>(Arrays.asList(input.split(",",-1)));if(!allowed.containsAll(result))invalid();return result;}
    private static void page(int page,int size) {if(page<0||page>1_000_000||size<1||size>100)invalid();}
    private static void invalid() {throw new ApiException(ErrorCode.INVALID_INPUT);}
    private static void conflict() {throw new ApiException(ErrorCode.CONFLICT);}
}
