package com.logssey.secret.policy;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.command.*;
import com.logssey.secret.policy.SecretPolicyContracts.*;
import com.logssey.secret.policy.SecretPolicyRepository.*;
import com.logssey.secret.snapshot.SecretReadSnapshots;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Current authority and change impact decide the approval route, never a client-supplied mode. */
@Service
@Transactional
public class SecretScopeChangeService {
    private static final String RULE="scope-change-v1";
    private final JdbcTemplate jdbc;
    private final SecretPolicyRepository repository;
    private final SecretStoragePolicyService policies;
    private final SecretAccessService access;
    private final SecretCommandExecutor commands;
    private final SecretReadSnapshots snapshots;

    public SecretScopeChangeService(JdbcTemplate jdbc,SecretPolicyRepository repository,SecretStoragePolicyService policies,
            SecretAccessService access,SecretCommandExecutor commands,SecretReadSnapshots snapshots) {
        this.jdbc=jdbc;this.repository=repository;this.policies=policies;this.access=access;this.commands=commands;this.snapshots=snapshots;
    }

    @Transactional(readOnly=true)
    public Preview preview(long scopeId,PreviewRequest request,String login) {
        var actor=access.requirePrincipal(login);var scope=readable(scopeId,actor,false);
        if(request==null)invalid();
        SecretCommandExecutor.requireExpectedVersion(request.expectedScopeVersion(),scope.originVersion());
        return prepare(scope,request.origin(),request.storagePolicyId(),request.storagePolicyVersion(),actor);
    }

    public Classification propose(long scopeId,ProposalRequest request,String login) {
        // Older clients retain their explicit independent proposal contract.
        if(request!=null && request.expectedApprovalMode()==null) return policies.propose(scopeId,request,login);
        if(request==null || !Set.of("DIRECT","INDEPENDENT_REVIEW").contains(Objects.toString(request.expectedApprovalMode(),"")))invalid();
        reference(request.evidenceRef());
        if(!Set.of("POLICY_PENDING","SOURCE_CLASSIFICATION","SOURCE_CORRECTION").contains(Objects.toString(request.reasonCode(),"")))invalid();
        if((request.storagePolicyId()==null)!=request.reasonCode().equals("POLICY_PENDING"))invalid();
        var actor=access.requirePrincipal(login);
        var result=commands.execute(actor,SecretCommandExecutor.Kind.SCOPE_CLASSIFICATION,request.idempotencyKey(),
            digest(scopeId,request.origin(),request.storagePolicyId(),request.storagePolicyVersion(),request.reasonCode(),
                request.evidenceRef(),request.expectedScopeVersion(),request.expectedApprovalMode(),request.reviewerUserId()),
            ()->requireChangeAuthority(readable(scopeId,actor,false),actor),()->{
                policies.lockGovernance();var scope=readable(scopeId,actor,true);
                SecretCommandExecutor.requireExpectedVersion(request.expectedScopeVersion(),scope.originVersion());
                var preview=prepare(scope,request.origin(),request.storagePolicyId(),request.storagePolicyVersion(),actor);
                if(!preview.approvalMode().equals(request.expectedApprovalMode()))conflict("APPROVAL_REQUIREMENT_CHANGED");
                if(preview.approvalMode().equals("DIRECT") && request.reviewerUserId()!=null)invalid();
                if(request.reviewerUserId()!=null && preview.eligibleReviewers().stream().noneMatch(r->r.userId()==request.reviewerUserId()))invalid();
                var pending=repository.pending(scopeId).orElse(null);
                if(pending!=null) {
                    if(pending.proposer()==actor.userId() && matches(pending,request))
                        return new SecretCommandResult(pending.id(),pending.version(),SecretCommandResult.Status.PENDING);
                    conflict("CLASSIFICATION_ALREADY_PENDING");
                }
                var approved=repository.approvedDecision(scopeId,scope.originVersion()).orElse(null);
                var binding=repository.binding(scopeId).orElse(null);
                if(approved!=null && approved.proposalId()!=null && scope.origin().equals(request.origin())
                        && Objects.equals(binding==null?null:binding.policyId(),request.storagePolicyId())
                        && Objects.equals(binding==null?null:binding.policyVersion(),request.storagePolicyVersion())
                        && Objects.equals(approved.evidenceRef(),request.evidenceRef())) {
                    var previous=repository.proposal(scopeId,approved.proposalId(),false).orElseThrow();
                    return new SecretCommandResult(previous.id(),previous.version(),SecretCommandResult.Status.UNCHANGED);
                }
                long id=jdbc.queryForObject("""
                    INSERT INTO secret_scope_classification_proposals(scope_id,expected_scope_version,scope_revision,scope_fingerprint,
                        proposed_origin,policy_id,policy_version,reason_code,evidence_ref,proposed_by_user_id,status,
                        approval_mode,approval_rule_version,reviewer_user_id)
                    VALUES(?,?,?,?,?,?,?,?,?,?,'PENDING_APPROVAL',?,?,?) RETURNING proposal_id
                    """,Long.class,scopeId,scope.originVersion(),scope.revision(),scope.fingerprint(),request.origin(),
                    request.storagePolicyId(),request.storagePolicyVersion(),request.reasonCode(),request.evidenceRef(),
                    actor.userId(),preview.approvalMode(),RULE,request.reviewerUserId());
                var proposal=repository.proposal(scopeId,id,true).orElseThrow();
                if(preview.approvalMode().equals("DIRECT")) {
                    policies.applyApprovedProposal(scope,proposal,actor);
                    return new SecretCommandResult(id,proposal.version()+1,SecretCommandResult.Status.APPROVED);
                }
                snapshots.invalidateScope(scopeId);
                return new SecretCommandResult(id,proposal.version(),SecretCommandResult.Status.PENDING);
            });
        return changed(scopeId,actor,login,result);
    }

    public Classification approve(long scopeId,long proposalId,ApproveProposalRequest request,String login) {
        if(request==null)invalid();
        if(request.idempotencyKey()==null)return policies.approveProposal(scopeId,proposalId,request,login);
        var actor=access.requirePrincipal(login);
        var result=commands.execute(actor,SecretCommandExecutor.Kind.SCOPE_CLASSIFICATION_APPROVE,request.idempotencyKey(),
            digest(scopeId,proposalId,request.expectedScopeVersion(),request.expectedProposalVersion()),
            ()->{var scope=readable(scopeId,actor,false);access.requireConnectionRole(actor,scope.connectionId(),SecretRole.SECURITY);
                var p=repository.proposal(scopeId,proposalId,false).orElseThrow(()->new ApiException(ErrorCode.NOT_FOUND));
                if(p.proposer()==actor.userId() || p.reviewerUserId()!=null && p.reviewerUserId()!=actor.userId())forbidden();},
            ()->{policies.approveProposal(scopeId,proposalId,request,login);var p=repository.proposal(scopeId,proposalId,false).orElseThrow();
                return new SecretCommandResult(p.id(),p.version(),SecretCommandResult.Status.APPROVED);});
        return changed(scopeId,actor,login,result);
    }

    public Classification assign(long scopeId,long proposalId,ReviewAssignmentRequest request,String login) {
        if(request==null)invalid();var actor=access.requirePrincipal(login);
        var result=commands.execute(actor,SecretCommandExecutor.Kind.SCOPE_REVIEWER_ASSIGN,request.idempotencyKey(),
            digest(scopeId,proposalId,request.reviewerUserId(),request.expectedProposalVersion()),
            ()->canAssign(scopeId,proposalId,actor,false),()->{
                policies.lockGovernance();var p=canAssign(scopeId,proposalId,actor,true);
                SecretCommandExecutor.requireExpectedVersion(request.expectedProposalVersion(),p.version());
                if(!p.status().equals("PENDING_APPROVAL"))conflict("PROPOSAL_NOT_PENDING");
                var scope=readable(scopeId,actor,false);
                if(request.reviewerUserId()!=null && repository.reviewers(scope.connectionId(),p.proposer()).stream()
                        .noneMatch(r->r.userId()==request.reviewerUserId()))invalid();
                jdbc.update("UPDATE secret_scope_classification_proposals SET reviewer_user_id=?,version=version+1 WHERE proposal_id=?",
                    request.reviewerUserId(),proposalId);
                snapshots.invalidateScope(scopeId);
                return new SecretCommandResult(proposalId,p.version()+1,SecretCommandResult.Status.PENDING);
            });
        return changed(scopeId,actor,login,result);
    }

    public Classification reject(long scopeId,long proposalId,RejectProposalRequest request,String login) {
        if(request==null)invalid();
        if(request.idempotencyKey()==null)return policies.rejectProposal(scopeId,proposalId,request,login);
        var actor=access.requirePrincipal(login);
        var result=commands.execute(actor,SecretCommandExecutor.Kind.SCOPE_CLASSIFICATION_REJECT,request.idempotencyKey(),
            digest(scopeId,proposalId,request.expectedProposalVersion(),request.reasonCode()),
            ()->{var scope=readable(scopeId,actor,false);access.requireConnectionRole(actor,scope.connectionId(),SecretRole.SECURITY);},
            ()->{policies.rejectProposal(scopeId,proposalId,request,login);var p=repository.proposal(scopeId,proposalId,false).orElseThrow();
                return new SecretCommandResult(p.id(),p.version(),SecretCommandResult.Status.REJECTED);});
        return changed(scopeId,actor,login,result);
    }

    private ProposalState canAssign(long scopeId,long proposalId,SecretPrincipal actor,boolean lock) {
        var scope=readable(scopeId,actor,lock);var p=repository.proposal(scopeId,proposalId,lock).orElseThrow(()->new ApiException(ErrorCode.NOT_FOUND));
        if(!scope.available() || !(access.hasConnectionRole(actor,scope.connectionId(),SecretRole.SECURITY)
                || p.proposer()==actor.userId() && access.hasConnectionRole(actor,scope.connectionId(),SecretRole.OPERATIONS)))forbidden();
        return p;
    }

    private Preview prepare(Scope scope,String origin,Long policyId,Long policyVersion,SecretPrincipal actor) {
        if(!Set.of("PRODUCTION","TEST").contains(Objects.toString(origin,"")) || (policyId==null)!=(policyVersion==null))invalid();
        if(!scope.available())conflict("SCOPE_UNAVAILABLE");
        policies.validateSupportedScope(scope);policies.preventFixtureMisclassification(scope,origin);
        var binding=repository.binding(scope.id()).orElse(null);
        boolean policyChanged=!Objects.equals(binding==null?null:binding.policyId(),policyId)
            || !Objects.equals(binding==null?null:binding.policyVersion(),policyVersion);
        if(policyId!=null && policyChanged) {
            var p=repository.policy(policyId,policyVersion,false).orElseThrow(()->new ApiException(ErrorCode.NOT_FOUND));
            if(!p.usable(repository.now()) || repository.rules(policyId,policyVersion).stream().noneMatch(r->r.scopeId()==scope.id()
                    && r.scopeRevision()==scope.revision() && r.fingerprint().equals(scope.fingerprint()) && r.contentType().equals(scope.contentType())))
                conflict("POLICY_SCOPE_MISMATCH");
        }
        var reasons=new ArrayList<String>();
        if(!access.hasConnectionRole(actor,scope.connectionId(),SecretRole.SECURITY))reasons.add("SECURITY_REVIEW_REQUIRED");
        if(origin.equals("TEST"))reasons.add("TEST_CLASSIFICATION_REQUIRES_REVIEW");
        if(policyChanged)reasons.add("POLICY_BINDING_CHANGE");
        String mode=reasons.isEmpty()?"DIRECT":"INDEPENDENT_REVIEW";
        var remaining=new ArrayList<String>();
        if(!policyChanged && policyId!=null)repository.setupReasons(scope.id()).stream().filter(r->r.startsWith("POLICY_")).forEach(remaining::add);
        if(policyId==null && Set.of("GITHUB_REPOSITORY_FILES","AWS_SECRETS_MANAGER_VALUE","AWS_SSM_PARAMETER_VALUE","AWS_S3_OBJECT_CONTENT").contains(scope.contentType()))remaining.add("POLICY_MISSING");
        if(mode.equals("INDEPENDENT_REVIEW"))remaining.add("PENDING_REVIEW");
        return new Preview(mode,List.copyOf(reasons),RULE,mode.equals("DIRECT")?List.of():repository.reviewers(scope.connectionId(),actor.userId()),
            repository.pending(scope.id()).isEmpty() && (access.hasConnectionRole(actor,scope.connectionId(),SecretRole.SECURITY)
                || access.hasConnectionRole(actor,scope.connectionId(),SecretRole.OPERATIONS)),List.copyOf(remaining));
    }

    private Classification changed(long scopeId,SecretPrincipal actor,String login,SecretCommandResult result) {
        readable(scopeId,actor,false);
        var p=repository.proposal(scopeId,result.targetId(),false).orElseThrow();
        var value=policies.classification(scopeId,login);
        Long decisionId=jdbc.query("SELECT decision_id FROM secret_scope_origin_decisions WHERE proposal_id=? AND decision='APPROVED'",
            (rs,row)->rs.getLong(1),p.id()).stream().findFirst().orElse(null);
        String effect=result.status()==SecretCommandResult.Status.UNCHANGED?"UNCHANGED":result.status()==SecretCommandResult.Status.PENDING?"PENDING_REVIEW":"APPLIED";
        return value.withChange(new ChangeResult(effect,p.id(),decisionId,p.approvalMode(),value.setupReasonCodes()));
    }
    private Scope readable(long id,SecretPrincipal actor,boolean lock) {
        var scope=repository.scope(id,lock).orElseThrow(()->new ApiException(ErrorCode.NOT_FOUND));
        access.requireConnectionFactsRead(actor,scope.connectionId());return scope;
    }
    private void requireChangeAuthority(Scope scope,SecretPrincipal actor) {
        if(!access.hasConnectionRole(actor,scope.connectionId(),SecretRole.SECURITY)
                && !access.hasConnectionRole(actor,scope.connectionId(),SecretRole.OPERATIONS))forbidden();
    }
    private static boolean matches(ProposalState p,ProposalRequest r) { return p.origin().equals(r.origin()) && Objects.equals(p.policyId(),r.storagePolicyId())
        && Objects.equals(p.policyVersion(),r.storagePolicyVersion()) && p.reason().equals(r.reasonCode()) && p.approvalMode().equals(r.expectedApprovalMode())
        && p.evidence().equals(r.evidenceRef()) && Objects.equals(p.reviewerUserId(),r.reviewerUserId()); }
    private static void reference(String s) { if(s==null || !s.matches("^((TICKET|CHANGE):[A-Z]{2,10}-[1-9][0-9]{0,9}|POLICY:SECRET-[1-9][0-9]{0,9})$"))invalid(); }
    private static byte[] digest(Object... values) { try{return MessageDigest.getInstance("SHA-256").digest(java.util.Arrays.toString(values).getBytes(StandardCharsets.UTF_8));}
        catch(java.security.NoSuchAlgorithmException e){throw new IllegalStateException(e);} }
    private static void invalid(){throw new ApiException(ErrorCode.INVALID_INPUT);}
    private static void forbidden(){throw new ApiException(ErrorCode.FORBIDDEN);}
    private static void conflict(String reason){throw new ApiException(ErrorCode.CONFLICT,reason);}
}
