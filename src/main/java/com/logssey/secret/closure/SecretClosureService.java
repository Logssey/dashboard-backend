package com.logssey.secret.closure;

import java.time.OffsetDateTime;
import java.util.*;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.command.*;
import com.logssey.secret.snapshot.SecretReadSnapshots;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;
import static com.logssey.secret.closure.SecretClosureContracts.*;
import static com.logssey.secret.closure.SecretClosureRepository.*;
import static com.logssey.secret.evidence.SecretEvidenceRules.*;
import static com.logssey.secret.snapshot.SecretReadSnapshots.facts;

@Service
public class SecretClosureService {
    private final SecretClosureRepository repository;
    private final SecretClosureEvaluator evaluator;
    private final SecretAccessService access;
    private final SecretCommandExecutor commands;
    private final SecretReadSnapshots snapshots;
    private final ObjectMapper json;
    public SecretClosureService(SecretClosureRepository repository,SecretClosureEvaluator evaluator,SecretAccessService access,
        SecretCommandExecutor commands,SecretReadSnapshots snapshots,ObjectMapper json) {
        this.repository=repository;this.evaluator=evaluator;this.access=access;this.commands=commands;this.snapshots=snapshots;this.json=json;
    }

    SecretAccessService access() {return access;}
    SecretCommandExecutor commands() {return commands;}
    SecretClosureEvaluator evaluator() {return evaluator;}

    @Transactional(readOnly=true,isolation=Isolation.REPEATABLE_READ)
    public ClosureChecks checks(String login,long id) {
        var actor=access.requirePrincipal(login);var inspection=evaluator.inspect(id,actor);
        var visible=repository.visible(actor,inspection.rows());if(visible.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);
        boolean full=repository.fullSecurity(actor,inspection.rows());
        Set<Long> visibleIds=new HashSet<>(visible.stream().map(row->number(row,"occurrence_id")).toList());
        var checks=inspection.checks().stream().filter(check->full||check.occurrenceId()!=null&&visibleIds.contains(check.occurrenceId())).toList();
        if(!full) {
            var restricted=new ArrayList<>(checks);
            restricted.add(new Check("COMPLETE_AUTHORIZATION","UNKNOWN","AUTHORIZED_SECURITY_COORDINATOR_REQUIRED",null,List.of()));checks=restricted;
        }
        var options=full?inspection.options():List.<CoverageOption>of();
        var dismissal=full?inspection.dismissalEvidence():Map.<String,List<EvidenceReference>>of();
        boolean active=active(inspection.caseRow());
        return new ClosureChecks(id,full?number(inspection.caseRow(),"version"):null,text(inspection.caseRow(),"case_origin"),
            full?inspection.version():null,repository.now(),!access.hasGlobalRole(actor,SecretRole.SECURITY),!options.isEmpty(),
            options.stream().map(CoverageOption::level).toList(),options,checks,
            group(inspection,"required",visibleIds),group(inspection,"unlinked",visibleIds),group(inspection,"unassessed",visibleIds),
            group(inspection,"authorized",visibleIds),group(inspection,"historical",visibleIds),"OTHER_ORIGINS_ARE_SEPARATE",
            new Capabilities(!options.isEmpty(),full&&active&&!inspection.remainingRiskIds().isEmpty(),full&&!dismissal.isEmpty()),
            List.copyOf(dismissal.keySet()),dismissal.values().stream().flatMap(Collection::stream).map(EvidenceReference::evidenceId).distinct().sorted().toList(),
            dismissal,lastResolution(id,actor,full),lastDismissal(id,actor,full));
    }

    public Mutation resolve(String login,long id,ResolutionRequest request) {
        if(request==null||!"RESOLVE".equals(request.decision())||request.closureCheckVersion()==null
            ||!request.closureCheckVersion().matches("[a-f0-9]{64}"))invalid();
        code(request.coverageLevel(),Set.of("FULL","LIMITED","SIMULATION"));
        var evidence=ids(request.evidenceIds());var actor=access.requirePrincipal(login);
        var result=commands.execute(actor,SecretCommandExecutor.Kind.CASE_RESOLUTION,request.idempotencyKey(),
            digest(id,request.decision(),request.expectedCaseVersion(),request.closureCheckVersion(),evidence,request.coverageLevel()),
            ()->requireFull(actor,id),()->{
                repository.lockUniverse(id);requireFull(actor,id);
                var inspection=evaluator.inspect(id,actor);var c=inspection.caseRow();requireActive(c);
                SecretCommandExecutor.requireExpectedVersion(request.expectedCaseVersion(),number(c,"version"));
                if(!request.closureCheckVersion().equals(inspection.version()))throw stale(inspection);
                var option=inspection.options().stream().filter(o->o.level().equals(request.coverageLevel())).findFirst()
                    .orElseThrow(()->new SecretClosureConflict(inspection.checks()));
                var allowed=new HashSet<>(inspection.options().stream().flatMap(o->o.evidenceIds().stream()).toList());
                if(!evidence.containsAll(option.evidenceIds())||!allowed.containsAll(evidence))throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
                long version=number(c,"version")+1;
                long check=repository.jdbc().queryForObject("""
                    INSERT INTO secret_case_resolution_checks(case_id,case_version,target_origin,version_digest,target_snapshot,check_results,allowed_coverage_levels)
                    VALUES(?,?,?,?,?::jsonb,?::jsonb,?::jsonb) RETURNING check_id
                    """,Long.class,id,c.get("version"),c.get("case_origin"),inspection.version(),json.writeValueAsString(inspection.targetSnapshot()),
                    json.writeValueAsString(inspection.checks()),json.writeValueAsString(inspection.options().stream().map(CoverageOption::level).toList()));
                long resolution=repository.jdbc().queryForObject("""
                    INSERT INTO secret_case_resolutions(case_id,resolved_by_user_id,reason_code,case_version,closure_check_id,coverage_level,evidence_snapshot,limitations)
                    VALUES(?,?,'POST_ACTION_REVALIDATION',?,?,?,?::jsonb,?::jsonb) RETURNING resolution_id
                    """,Long.class,id,actor.userId(),version,check,option.level(),json.writeValueAsString(facts("evidenceIds",evidence,
                        "targetOrigin",c.get("case_origin"),"closureCheckVersion",inspection.version())),json.writeValueAsString(option.limitations()));
                for(var row:inspection.rows())if(inspection.groups().get("required").stream().anyMatch(location->location.occurrenceId()==number(row,"occurrence_id")))
                    repository.jdbc().update("""
                        INSERT INTO secret_case_resolution_locations(case_id,occurrence_id,revalidation_id,resolution_id,action_cycle,last_material_action_id)
                        VALUES(?,?,?,?,?,?)
                        """,id,row.get("occurrence_id"),row.get("revalidation_id"),resolution,row.get("action_cycle"),row.get("last_material_action_id"));
                repository.jdbc().update("UPDATE secret_response_cases SET action_status='RESOLVED',version=?,resolved_at=clock_timestamp(),updated_at=clock_timestamp() WHERE case_id=?",version,id);
                repository.jdbc().update("UPDATE secret_case_occurrences SET response_status='RESOLVED',version=version+1,resolved_at=clock_timestamp() WHERE case_id=?",id);
                repository.jdbc().update("""
                    INSERT INTO secret_case_stage_history(case_id,from_status,to_status,reason_code,actor_user_id,case_version)
                    VALUES(?,?,'RESOLVED','POST_ACTION_REVALIDATION',?,?)
                    """,id,c.get("action_status"),actor.userId(),version);
                activity(id,"CASE_RESOLVED",actor,version,resolution);invalidate(inspection);
                return new SecretCommandResult(id,version,SecretCommandResult.Status.RESOLVED);
            });
        var record=repository.jdbc().queryForMap("SELECT resolution_id,coverage_level FROM secret_case_resolutions WHERE case_id=? AND case_version=?",id,result.version());
        return new Mutation(id,result.version(),"RESOLVED",number(record,"resolution_id"),text(record,"coverage_level"),null,null,null,true);
    }

    public Mutation dismiss(String login,long id,DismissalRequest request) {
        if(request==null)invalid();code(request.reasonCode(),Set.of("FALSE_POSITIVE","OUT_OF_SCOPE"));
        var evidence=ids(request.evidenceIds());var actor=access.requirePrincipal(login);
        var result=commands.execute(actor,SecretCommandExecutor.Kind.CASE_DISMISSAL,request.idempotencyKey(),digest(id,request.reasonCode(),evidence,request.expectedCaseVersion()),
            ()->requireFull(actor,id),()->{
                repository.lockUniverse(id);requireFull(actor,id);var inspection=evaluator.inspect(id,actor);var c=inspection.caseRow();requireActive(c);
                SecretCommandExecutor.requireExpectedVersion(request.expectedCaseVersion(),number(c,"version"));
                var eligible=inspection.dismissalEvidence().getOrDefault(request.reasonCode(),List.of()).stream().map(EvidenceReference::evidenceId).toList();
                if(eligible.isEmpty()||!evidence.containsAll(eligible)||!eligible.containsAll(evidence))throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
                String transfer=null;
                if("OUT_OF_SCOPE".equals(request.reasonCode()))transfer=repository.jdbc().queryForObject("SELECT accepted_transfer_ref FROM secret_case_transfer_evidence WHERE evidence_id=? AND case_id=?",String.class,evidence.getFirst(),id);
                long version=number(c,"version")+1;
                long dismissal=repository.jdbc().queryForObject("""
                    INSERT INTO secret_case_dismissals(case_id,reason_code,evidence_snapshot,accepted_transfer_ref,approved_by_user_id,case_version)
                    VALUES(?,?,?::jsonb,?,?,?) RETURNING dismissal_id
                    """,Long.class,id,request.reasonCode(),json.writeValueAsString(facts("evidenceIds",evidence,"target",inspection.targetSnapshot())),transfer,actor.userId(),version);
                repository.jdbc().update("UPDATE secret_response_cases SET disposition=?,is_current=false,closed_at=clock_timestamp(),updated_at=clock_timestamp(),version=? WHERE case_id=?",request.reasonCode(),version,id);
                activity(id,"CASE_DISMISSED",actor,version,dismissal);invalidate(inspection);
                return new SecretCommandResult(dismissal,version,SecretCommandResult.Status.CLOSED);
            });
        return new Mutation(id,result.version(),"CLOSED",null,null,result.targetId(),null,null,true);
    }

    /** Internal aggregation: caller must already have filtered the cases it may display. */
    @Transactional(readOnly=true)
    public boolean isFullyRiskAccepted(long id) {return riskAcceptanceDeadline(id)!=null;}

    /** Public read-model callers must use the subject-aware form to avoid hidden-location signals. */
    @Transactional(readOnly=true)
    public OffsetDateTime riskAcceptanceDeadline(long id,String login) {
        var actor=access.requirePrincipal(login);var rows=repository.related(id);
        if(!repository.fullSecurity(actor,rows))return null;
        return riskAcceptanceDeadline(id);
    }

    @Transactional(readOnly=true)
    public OffsetDateTime riskAcceptanceDeadline(long id) {
        var inspection=evaluator.inspect(id);if(!active(inspection.caseRow())||inspection.remainingRiskIds().isEmpty())return null;
        OffsetDateTime deadline=null;
        for(Long occurrence:inspection.remainingRiskIds()) {
            OffsetDateTime expires=repository.jdbc().queryForObject("""
                SELECT max(e.expires_at) FROM secret_exception_occurrences coverage JOIN secret_exceptions e USING(exception_id)
                JOIN secret_occurrences o ON o.occurrence_id=coverage.occurrence_id JOIN secret_connection_scopes s ON s.scope_id=o.scope_id
                WHERE e.case_id=? AND coverage.occurrence_id=? AND e.revoked_at IS NULL AND e.expires_at>clock_timestamp()
                 AND coverage.scope_revision=s.revision AND coverage.scope_origin_version=s.response_origin_version
                 AND coverage.assessment_version=o.exposure_assessment_version
                """,OffsetDateTime.class,id,occurrence);
            if(expires==null)return null;if(deadline==null||expires.isBefore(deadline))deadline=expires;
        }
        return deadline;
    }

    void requireFull(SecretPrincipal actor,long id) {
        var rows=repository.related(id);
        if(repository.visible(actor,rows).isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);
        if(!repository.fullSecurity(actor,rows))throw new ApiException(ErrorCode.FORBIDDEN);
    }
    void invalidate(SecretClosureEvaluator.Inspection inspection) {inspection.rows().forEach(row->snapshots.invalidateOccurrence(number(row,"occurrence_id")));}
    void activity(long id,String type,SecretPrincipal actor,long version,long reference) {
        repository.jdbc().update("INSERT INTO secret_location_activities(case_id,activity_type,actor_user_id,case_version,reference_id) VALUES(?,?,?,?,?)",id,type,actor.userId(),version,reference);
    }
    static boolean active(Map<String,Object> c) {return yes(c,"is_current")&&"IN_SCOPE".equals(c.get("disposition"))&&!"RESOLVED".equals(c.get("action_status"));}
    static void requireActive(Map<String,Object> c) {if(!active(c))throw new ApiException(ErrorCode.CONFLICT);}
    static List<Long> ids(List<Long> values) {
        if(values==null)return List.of();if(values.size()>500||values.stream().anyMatch(v->v==null||v<=0)||new HashSet<>(values).size()!=values.size())invalid();
        return values.stream().sorted().toList();
    }
    private SecretClosureConflict stale(SecretClosureEvaluator.Inspection inspection) {
        var checks=new ArrayList<>(inspection.checks());checks.add(new Check("CONTEXT_VERSION","UNKNOWN","CLOSURE_EVIDENCE_CHANGED",null,List.of()));
        return new SecretClosureConflict(checks);
    }
    private LocationGroup group(SecretClosureEvaluator.Inspection inspection,String name,Set<Long> visible) {
        var items=inspection.groups().get(name).stream().filter(location->visible.contains(location.occurrenceId())).toList();
        return new LocationGroup("Occurrence",items,items.size());
    }
    private LastResolution lastResolution(long id,SecretPrincipal actor,boolean full) {
        var records=repository.jdbc().queryForList("SELECT * FROM secret_case_resolutions WHERE case_id=?",id);if(records.isEmpty())return null;
        var row=records.getFirst();return new LastResolution(number(row,"resolution_id"),row.get("coverage_level")==null?"UNKNOWN_LEGACY":text(row,"coverage_level"),
            time(row,"resolved_at"),historyEvidence(row,"evidence_snapshot",actor,full),row.get("limitations")==null?
                List.of("LEGACY_VERIFICATION_EVIDENCE_UNAVAILABLE"):json.readValue(row.get("limitations").toString(),List.class));
    }
    private LastDismissal lastDismissal(long id,SecretPrincipal actor,boolean full) {
        var records=repository.jdbc().queryForList("SELECT * FROM secret_case_dismissals WHERE case_id=?",id);if(records.isEmpty())return null;
        var row=records.getFirst();return new LastDismissal(number(row,"dismissal_id"),text(row,"reason_code"),time(row,"created_at"),historyEvidence(row,"evidence_snapshot",actor,full));
    }
    private List<Long> historyEvidence(Map<String,Object> row,String column,SecretPrincipal actor,boolean full) {
        if(row.get(column)==null)return List.of();var facts=json.readValue(row.get(column).toString(),Map.class);
        var evidence=((List<?>)facts.getOrDefault("evidenceIds",List.of())).stream().map(value->((Number)value).longValue()).toList();
        if(full)return evidence;
        var visible=new HashSet<Long>();
        for(var e:repository.jdbc().queryForList("SELECT evidence_id,source_occurrence_id FROM secret_credential_lifecycle_evidence WHERE case_id=?",row.get("case_id")))
            if(repository.readable(actor,number(e,"source_occurrence_id")))visible.add(number(e,"evidence_id"));
        for(var e:repository.jdbc().queryForList("SELECT revalidation_id,occurrence_id FROM secret_case_revalidations WHERE case_id=?",row.get("case_id")))
            if(repository.readable(actor,number(e,"occurrence_id")))visible.add(number(e,"revalidation_id"));
        return evidence.stream().filter(visible::contains).toList();
    }
    static void invalid() {throw new ApiException(ErrorCode.INVALID_INPUT);}
}
