package com.logssey.secret.closure;

import java.util.*;
import java.time.OffsetDateTime;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.command.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import static com.logssey.secret.closure.SecretClosureContracts.*;
import static com.logssey.secret.closure.SecretClosureRepository.*;
import static com.logssey.secret.closure.SecretClosureService.*;
import static com.logssey.secret.evidence.SecretEvidenceRules.*;

@Service
public class SecretGovernanceService {
    private static final Set<String> EXCEPTION_REASONS=Set.of("BUSINESS_CONTINUITY","TEMPORARY_DEPENDENCY","COMPENSATING_CONTROL");
    private static final Set<String> REVOKE_REASONS=Set.of("RISK_REDUCED","APPROVAL_WITHDRAWN","SCOPE_CHANGED");
    private static final Set<String> TRANSFER_REASONS=Set.of("PROGRAM_SCOPE_ENDED","OWNER_TRANSFER");
    private static final Map<String,List<String>> REVIEW_REASONS=Map.of("APPROVE",List.of("TRANSFER_AND_ACCEPTANCE_CONFIRMED"),
        "REJECT",List.of("INSUFFICIENT_EVIDENCE","WRONG_SCOPE"));
    private final SecretClosureService closure;
    private final SecretClosureRepository repository;
    public SecretGovernanceService(SecretClosureService closure,SecretClosureRepository repository) {this.closure=closure;this.repository=repository;}

    @Transactional(readOnly=true,isolation=Isolation.REPEATABLE_READ)
    public Exceptions exceptions(String login,long id) {
        var actor=closure.access.requirePrincipal(login);var inspection=closure.evaluator.inspect(id,actor);
        var visible=repository.visible(actor,inspection.rows());if(visible.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);
        boolean full=repository.fullSecurity(actor,inspection.rows()),canApprove=full&&active(inspection.caseRow());
        var visibleIds=new HashSet<>(visible.stream().map(row->number(row,"occurrence_id")).toList());
        var items=new ArrayList<ExceptionItem>();
        for(var e:repository.jdbc.queryForList("SELECT * FROM secret_exceptions WHERE case_id=? ORDER BY approved_at DESC,exception_id DESC",id)) {
            var covered=repository.jdbc.query("SELECT occurrence_id FROM secret_exception_occurrences WHERE exception_id=? ORDER BY occurrence_id",(rs,n)->rs.getLong(1),e.get("exception_id"))
                .stream().filter(visibleIds::contains).toList();if(covered.isEmpty())continue;
            String status=e.get("revoked_at")!=null?"REVOKED":time(e,"expires_at").isAfter(repository.now())?"ACTIVE":"EXPIRED";
            boolean applicable="ACTIVE".equals(status)&&!staleException(number(e,"exception_id"),visibleIds);
            if("ACTIVE".equals(status)&&!applicable)status="SCOPE_CHANGED";
            items.add(new ExceptionItem(number(e,"exception_id"),text(e,"reason_code"),full?text(e,"evidence_ref"):null,
                number(e,"approved_by_user_id"),time(e,"approved_at"),time(e,"expires_at"),time(e,"revoked_at"),status,covered,
                applicable,canApprove&&e.get("revoked_at")==null&&time(e,"expires_at").isAfter(repository.now())));
        }
        var alreadyCovered=new HashSet<>(repository.jdbc.query("""
            SELECT coverage.occurrence_id FROM secret_exception_occurrences coverage JOIN secret_exceptions e USING(exception_id)
            WHERE e.case_id=? AND e.revoked_at IS NULL AND e.expires_at>clock_timestamp()
            """,(rs,n)->rs.getLong(1),id));
        var eligible=full?inspection.remainingRiskIds().stream().filter(occurrence->!alreadyCovered.contains(occurrence))
            .map(occurrence->new Location(occurrence,"위치 #"+occurrence,"UNKNOWN","RISK_REMAINS")).toList():List.<Location>of();
        return new Exceptions(id,full?number(inspection.caseRow(),"version"):null,items,canApprove,
            EXCEPTION_REASONS.stream().sorted().toList(),REVOKE_REASONS.stream().sorted().toList(),eligible,90,
            full&&closure.isFullyRiskAccepted(id),!closure.access.hasGlobalRole(actor,SecretRole.SECURITY));
    }
    public Mutation approveException(String login,long id,ExceptionRequest request) {
        if(request==null)invalid();code(request.reasonCode(),EXCEPTION_REASONS);reference(request.evidenceRef(),true);
        var occurrences=ids(request.occurrenceIds());if(occurrences.isEmpty()||request.expiresAt()==null)invalid();
        var actor=closure.access.requirePrincipal(login);
        var result=closure.commands.execute(actor,SecretCommandExecutor.Kind.RISK_EXCEPTION_APPROVE,request.idempotencyKey(),
            digest(id,occurrences,request.reasonCode(),request.evidenceRef(),request.expiresAt(),request.expectedCaseVersion()),()->closure.requireFull(actor,id),()->{
                repository.lockUniverse(id);closure.requireFull(actor,id);var inspection=closure.evaluator.inspect(id,actor);var c=inspection.caseRow();requireActive(c);
                SecretCommandExecutor.requireExpectedVersion(request.expectedCaseVersion(),number(c,"version"));
                var now=repository.now();if(!request.expiresAt().isAfter(now)||request.expiresAt().isAfter(now.plusDays(90)))invalid();
                if(!inspection.remainingRiskIds().containsAll(occurrences))throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
                boolean overlap=occurrences.stream().anyMatch(occurrence->Boolean.TRUE.equals(repository.jdbc.queryForObject("""
                    SELECT EXISTS(SELECT 1 FROM secret_exception_occurrences coverage JOIN secret_exceptions e USING(exception_id)
                      WHERE e.case_id=? AND coverage.occurrence_id=? AND e.revoked_at IS NULL AND e.expires_at>clock_timestamp())
                    """,Boolean.class,id,occurrence)));
                if(overlap)throw new ApiException(ErrorCode.CONFLICT);
                long version=number(c,"version")+1;
                long exception=repository.jdbc.queryForObject("""
                    INSERT INTO secret_exceptions(case_id,reason_code,evidence_ref,approved_by_user_id,approved_at,expires_at,approved_case_version)
                    VALUES(?,?,?,?,?,?,?) RETURNING exception_id
                    """,Long.class,id,request.reasonCode(),request.evidenceRef(),actor.userId(),now,request.expiresAt(),version);
                for(Long occurrence:occurrences)repository.jdbc.update("""
                    INSERT INTO secret_exception_occurrences(exception_id,occurrence_id,scope_id,scope_revision,scope_origin_version,assessment_version)
                    SELECT ?,o.occurrence_id,s.scope_id,s.revision,s.response_origin_version,o.exposure_assessment_version
                    FROM secret_occurrences o JOIN secret_connection_scopes s ON s.scope_id=o.scope_id WHERE o.occurrence_id=?
                    """,exception,occurrence);
                bump(id,version);closure.activity(id,"EXCEPTION_APPROVED",actor,version,exception);closure.invalidate(inspection);
                return new SecretCommandResult(exception,version,SecretCommandResult.Status.APPROVED);
            });
        return new Mutation(id,result.version(),"APPROVED",null,null,null,result.targetId(),null,true);
    }
    public Mutation revoke(String login,long id,RevokeRequest request) {
        if(request==null||request.exceptionId()==null||request.exceptionId()<=0)invalid();code(request.reasonCode(),REVOKE_REASONS);
        var actor=closure.access.requirePrincipal(login);
        var result=closure.commands.execute(actor,SecretCommandExecutor.Kind.RISK_EXCEPTION_REVOKE,request.idempotencyKey(),
            digest(id,request.exceptionId(),request.reasonCode(),request.expectedCaseVersion()),()->closure.requireFull(actor,id),()->{
                repository.lockUniverse(id);closure.requireFull(actor,id);var inspection=closure.evaluator.inspect(id,actor);var c=inspection.caseRow();requireActive(c);
                SecretCommandExecutor.requireExpectedVersion(request.expectedCaseVersion(),number(c,"version"));
                var records=repository.jdbc.queryForList("SELECT * FROM secret_exceptions WHERE exception_id=? AND case_id=? FOR UPDATE",request.exceptionId(),id);
                if(records.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);var e=records.getFirst();
                if(e.get("revoked_at")!=null||!time(e,"expires_at").isAfter(repository.now()))throw new ApiException(ErrorCode.CONFLICT);
                long version=number(c,"version")+1;
                repository.jdbc.update("UPDATE secret_exceptions SET revoked_at=clock_timestamp(),revoked_by_user_id=?,revoke_reason_code=? WHERE exception_id=?",actor.userId(),request.reasonCode(),request.exceptionId());
                bump(id,version);closure.activity(id,"EXCEPTION_REVOKED",actor,version,request.exceptionId());closure.invalidate(inspection);
                return new SecretCommandResult(request.exceptionId(),version,SecretCommandResult.Status.CLOSED);
            });
        return new Mutation(id,result.version(),"REVOKED",null,null,null,result.targetId(),null,true);
    }

    @Transactional(readOnly=true,isolation=Isolation.REPEATABLE_READ)
    public TransferList transfers(String login,long id) {
        var actor=closure.access.requirePrincipal(login);var c=repository.caseRow(id,false);var rows=repository.related(id);
        var visible=repository.visible(actor,rows);if(visible.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);
        boolean full=repository.fullSecurity(actor,rows),active=active(c);var items=new ArrayList<TransferEvidence>();
        var visibleIds=new HashSet<>(visible.stream().map(row->number(row,"occurrence_id")).toList());
        for(var e:repository.jdbc.queryForList("""
            SELECT e.*,1+(SELECT count(*) FROM secret_case_transfer_reviews WHERE evidence_id=e.evidence_id) AS version,
              review.decision,review.reviewed_by_user_id FROM secret_case_transfer_evidence e
            LEFT JOIN LATERAL(SELECT decision,reviewed_by_user_id FROM secret_case_transfer_reviews r WHERE r.evidence_id=e.evidence_id
              ORDER BY review_id DESC LIMIT 1)review ON true WHERE e.case_id=? ORDER BY e.evidence_id DESC
            """,id)) {
            var covered=repository.jdbc.query("SELECT occurrence_id FROM secret_case_transfer_locations WHERE evidence_id=? ORDER BY occurrence_id",(rs,n)->rs.getLong(1),e.get("evidence_id"))
                .stream().filter(visibleIds::contains).toList();if(covered.isEmpty())continue;
            items.add(new TransferEvidence(number(e,"evidence_id"),number(e,"version"),text(e,"reason_code"),full?text(e,"evidence_ref"):null,
                full?text(e,"accepted_transfer_ref"):null,covered,number(e,"submitted_by_user_id"),time(e,"submitted_at"),
                e.get("decision")==null?"PENDING":"APPROVE".equals(e.get("decision"))?"APPROVED":"REJECTED",nullable(e,"reviewed_by_user_id"),
                full&&active&&actor.userId()!=number(e,"submitted_by_user_id")&&!staleTransfer(number(e,"evidence_id"))));
        }
        return new TransferList(id,full?number(c,"version"):null,items,full&&active,TRANSFER_REASONS.stream().sorted().toList(),REVIEW_REASONS);
    }
    public Mutation transfer(String login,long id,TransferRequest request) {
        if(request==null)invalid();code(request.reasonCode(),TRANSFER_REASONS);
        if(!transferReference(request.evidenceRef())||!transferReference(request.acceptedTransferRef()))invalid();
        var occurrences=ids(request.occurrenceIds());if(occurrences.isEmpty())invalid();var actor=closure.access.requirePrincipal(login);
        var result=closure.commands.execute(actor,SecretCommandExecutor.Kind.TRANSFER_SUBMIT,request.idempotencyKey(),
            digest(id,occurrences,request.reasonCode(),request.evidenceRef(),request.acceptedTransferRef(),request.expectedCaseVersion()),()->closure.requireFull(actor,id),()->{
                repository.lockUniverse(id);closure.requireFull(actor,id);var c=repository.caseRow(id,false);requireActive(c);
                SecretCommandExecutor.requireExpectedVersion(request.expectedCaseVersion(),number(c,"version"));
                var linked=repository.jdbc.query("SELECT occurrence_id FROM secret_case_occurrences WHERE case_id=?",(rs,n)->rs.getLong(1),id);
                if(!linked.containsAll(occurrences))throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
                long version=number(c,"version")+1;
                long evidence=repository.jdbc.queryForObject("""
                    INSERT INTO secret_case_transfer_evidence(case_id,reason_code,evidence_ref,accepted_transfer_ref,submitted_by_user_id,case_version)
                    VALUES(?,?,?,?,?,?) RETURNING evidence_id
                    """,Long.class,id,request.reasonCode(),request.evidenceRef(),request.acceptedTransferRef(),actor.userId(),version);
                for(Long occurrence:occurrences)repository.jdbc.update("""
                    INSERT INTO secret_case_transfer_locations(evidence_id,occurrence_id,scope_id,scope_revision,scope_origin_version,assessment_version)
                    SELECT ?,o.occurrence_id,s.scope_id,s.revision,s.response_origin_version,o.exposure_assessment_version
                    FROM secret_occurrences o JOIN secret_connection_scopes s ON s.scope_id=o.scope_id WHERE o.occurrence_id=?
                    """,evidence,occurrence);
                bump(id,version);closure.activity(id,"TRANSFER_SUBMITTED",actor,version,evidence);
                closure.invalidate(closure.evaluator.inspect(id,actor));return new SecretCommandResult(evidence,version,SecretCommandResult.Status.PENDING);
            });
        return new Mutation(id,result.version(),"PENDING",null,null,null,null,result.targetId(),true);
    }
    public Mutation reviewTransfer(String login,long id,long evidence,TransferReview request) {
        if(request==null||!REVIEW_REASONS.getOrDefault(request.decision()==null?"":request.decision(),List.of()).contains(request.reasonCode()))invalid();
        var actor=closure.access.requirePrincipal(login);
        var result=closure.commands.execute(actor,SecretCommandExecutor.Kind.TRANSFER_REVIEW,request.idempotencyKey(),
            digest(id,evidence,request.decision(),request.reasonCode(),request.expectedEvidenceVersion(),request.expectedCaseVersion()),()->closure.requireFull(actor,id),()->{
                repository.lockUniverse(id);closure.requireFull(actor,id);var c=repository.caseRow(id,false);requireActive(c);
                SecretCommandExecutor.requireExpectedVersion(request.expectedCaseVersion(),number(c,"version"));
                var records=repository.jdbc.queryForList("SELECT * FROM secret_case_transfer_evidence WHERE case_id=? AND evidence_id=? FOR UPDATE",id,evidence);
                if(records.isEmpty())throw new ApiException(ErrorCode.NOT_FOUND);var e=records.getFirst();
                if(number(e,"submitted_by_user_id")==actor.userId())throw new ApiException(ErrorCode.FORBIDDEN);
                long evidenceVersion=repository.jdbc.queryForObject("SELECT 1+count(*) FROM secret_case_transfer_reviews WHERE evidence_id=?",Long.class,evidence);
                SecretCommandExecutor.requireExpectedVersion(request.expectedEvidenceVersion(),evidenceVersion);
                if(staleTransfer(evidence))throw new ApiException(ErrorCode.CONFLICT);
                long version=number(c,"version")+1;
                repository.jdbc.update("""
                    INSERT INTO secret_case_transfer_reviews(evidence_id,decision,reason_code,expected_evidence_version,case_version,reviewed_by_user_id)
                    VALUES(?,?,?,?,?,?)
                    """,evidence,request.decision(),request.reasonCode(),evidenceVersion,version,actor.userId());
                bump(id,version);closure.activity(id,"TRANSFER_REVIEWED",actor,version,evidence);closure.invalidate(closure.evaluator.inspect(id,actor));
                return new SecretCommandResult(evidence,version,"APPROVE".equals(request.decision())?SecretCommandResult.Status.APPROVED:SecretCommandResult.Status.REJECTED);
            });
        return new Mutation(id,result.version(),result.status().name(),null,null,null,null,result.targetId(),true);
    }
    private boolean staleException(long exception,Set<Long> visibleIds) {
        // A hidden scope change must not change another subject's projected exception state.
        return repository.jdbc.query("""
            SELECT coverage.occurrence_id FROM secret_exception_occurrences coverage JOIN secret_occurrences o USING(occurrence_id)
                JOIN secret_connection_scopes s ON s.scope_id=o.scope_id WHERE coverage.exception_id=?
                AND (coverage.scope_revision<>s.revision OR coverage.scope_origin_version<>s.response_origin_version
                    OR coverage.assessment_version<>o.exposure_assessment_version)
            """,(rs,n)->rs.getLong(1),exception).stream().anyMatch(visibleIds::contains);
    }
    private boolean staleTransfer(long evidence) {
        return Boolean.TRUE.equals(repository.jdbc.queryForObject("""
            SELECT EXISTS(SELECT 1 FROM secret_case_transfer_locations l JOIN secret_occurrences o USING(occurrence_id)
              JOIN secret_connection_scopes s ON s.scope_id=o.scope_id WHERE l.evidence_id=?
               AND (l.scope_revision<>s.revision OR l.scope_origin_version<>s.response_origin_version OR l.assessment_version<>o.exposure_assessment_version))
            """,Boolean.class,evidence));
    }
    private void bump(long id,long version) {repository.jdbc.update("UPDATE secret_response_cases SET version=?,updated_at=clock_timestamp() WHERE case_id=?",version,id);}
    private static boolean transferReference(String ref) {return ref!=null&&ref.matches("(TICKET|CHANGE):[A-Z]{2,10}-[1-9][0-9]{0,9}");}
}
