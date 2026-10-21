package com.logssey.secret.policy;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.access.SecretPrincipal;
import com.logssey.secret.access.SecretRole;
import com.logssey.secret.command.SecretCommandExecutor;
import com.logssey.secret.policy.SecretPolicyContracts.*;
import com.logssey.secret.policy.SecretPolicyRepository.*;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SecretStoragePolicyService {
    private static final Set<SecretRole> READ_ROLES=Set.of(SecretRole.SECURITY,SecretRole.OPERATIONS);
    private static final Set<String> CONTENT_TYPES=Set.of("GITHUB_REPOSITORY_FILES","AWS_SECRETS_MANAGER_VALUE",
            "AWS_SSM_PARAMETER_VALUE","AWS_S3_OBJECT_CONTENT");
    private static final Set<String> SOURCE_TYPES=Set.of("GITHUB_REPOSITORY_FILES","AWS_SECRETS_MANAGER_VALUE",
            "AWS_SSM_PARAMETER_VALUE","AWS_S3_OBJECT_CONTENT","IAM_ACCESS_KEY_METADATA",
            "AWS_SECRETS_MANAGER_METADATA","AWS_SSM_PARAMETER_METADATA","AWS_S3_BUCKET_METADATA");
    private static final Pattern EVIDENCE=Pattern.compile("^((TICKET|CHANGE):[A-Z]{2,10}-[1-9][0-9]{0,9}|POLICY:SECRET-[1-9][0-9]{0,9})$");
    private static final Pattern GITHUB=Pattern.compile("^github://([A-Za-z0-9-]{1,39})/([A-Za-z0-9_.-]{1,100})/([^/?#]+)/(.+/)$");
    private static final Pattern SENSITIVE_VALUE=Pattern.compile(".*(?:AKIA[A-Z0-9]{16}|ASIA[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|(?:secret_|ntn_)[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{20,}|AIza[A-Za-z0-9_-]{30,}).*");
    private final org.springframework.jdbc.core.JdbcTemplate jdbc;
    private final SecretPolicyRepository repository;
    private final SecretAccessService access;
    private final com.logssey.secret.snapshot.SecretReadSnapshots snapshots;

    SecretStoragePolicyService(SecretPolicyRepository repository,SecretAccessService access,org.springframework.jdbc.core.JdbcTemplate jdbc,
                                com.logssey.secret.snapshot.SecretReadSnapshots snapshots) {
        this.jdbc=jdbc;
        this.repository=repository;
        this.access=access;
        this.snapshots=snapshots;
    }

    @Transactional(readOnly=true)
    public Page<Classification> scopes(String status,int page,int size,String login) {
        var actor=reader(login);
        pagination(page,size);
        if (!allowed(status,"NEEDS_REVIEW","ALL")) invalid();
        // Filter before pagination/counts; OPERATIONS sees governance metadata, never occurrence details.
        List<Long> visible=jdbc.query("""
                SELECT s.scope_id FROM secret_connection_scopes s WHERE EXISTS (
                    SELECT 1 FROM secret_role_grants g WHERE g.user_id=? AND g.revoked_at IS NULL
                      AND g.role IN ('SECURITY','OPERATIONS') AND (g.connection_id IS NULL OR g.connection_id=s.connection_id)
                ) ORDER BY s.scope_id
                """,(rs,row)->rs.getLong(1),actor.userId()).stream().filter(id -> {
                    var scope=repository.scope(id,false).orElseThrow();
                    return canReadScope(actor,scope) && ("ALL".equals(status) || needsReview(scope));
                }).toList();
        var items=visible.stream().skip((long)page*size).limit(size)
                .map(id->classification(repository.scope(id,false).orElseThrow(),actor,false)).toList();
        return new Page<>(items,visible.size(),page,size);
    }

    @Transactional(readOnly=true)
    public Classification classification(long scopeId,String login) {
        var actor=reader(login);
        var scope=scope(scopeId,false);
        requireReadScope(actor,scope);
        return classification(scope,actor,false);
    }

    @Transactional(readOnly=true)
    public Page<PolicySummary> policies(String status,int page,int size,String login) {
        var actor=reader(login);
        pagination(page,size);
        if (!allowed(status,"ALL","ACTIVE","DRAFT","RETIRED")) invalid();
        var ids=jdbc.query("""
                SELECT policy_id,version FROM secret_storage_policies
                WHERE (?='ALL' OR status=?)
                  AND EXISTS (SELECT 1 FROM secret_storage_policy_rules r WHERE r.policy_id=secret_storage_policies.policy_id
                      AND r.policy_version=secret_storage_policies.version)
                  AND NOT EXISTS (SELECT 1 FROM secret_storage_policy_rules r
                      WHERE r.policy_id=secret_storage_policies.policy_id AND r.policy_version=secret_storage_policies.version
                        AND NOT EXISTS (SELECT 1 FROM secret_role_grants g
                            WHERE g.user_id=? AND g.revoked_at IS NULL AND g.role IN ('SECURITY','OPERATIONS')
                              AND (g.connection_id IS NULL OR g.connection_id=r.connection_id)))
                ORDER BY policy_id DESC,version DESC
                """,(rs,row)->new long[]{rs.getLong(1),rs.getLong(2)},status,status,actor.userId());
        var items=ids.stream().skip((long)page*size).limit(size)
                .map(id->summary(repository.policy(id[0],id[1],false).orElseThrow(),actor,false)).toList();
        return new Page<>(items,ids.size(),page,size);
    }

    @Transactional(readOnly=true)
    public PolicySummary policy(long policyId,long version,String login) {
        var actor=reader(login);
        var policy=policy(policyId,version,false);
        if (!canReadPolicy(actor,repository.rules(policyId,version))) notFound();
        return summary(policy,actor,false);
    }

    @Transactional
    public PolicySummary draft(DraftRequest request,String login) {
        var actor=access.requirePrincipal(login);
        lockGovernance();
        if (request==null || request.rules()==null || request.rules().isEmpty() || request.rules().size()>50
                || request.validFrom()==null || request.validUntil()!=null && !request.validUntil().isAfter(request.validFrom())
                || !allowed(request.reasonCode(),"AUTHORIZED_STORAGE","PROHIBITED_STORAGE","POLICY_UPDATE")) invalid();
        evidence(request.evidenceRef());
        if ((request.policyId()==null)!=(request.expectedVersion()==null)) invalid();
        long id;
        long version;
        if (request.policyId()==null) {
            id=jdbc.queryForObject("SELECT nextval('secret_storage_policy_id_seq')",Long.class);
            version=1;
        } else {
            var latest=latestVersion(request.policyId());
            SecretCommandExecutor.requireExpectedVersion(request.expectedVersion(),latest);
            requireSecurityForPolicy(actor,repository.rules(request.policyId(),latest));
            if (jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM secret_storage_policies WHERE policy_id=? AND status='DRAFT')",
                    Boolean.class,request.policyId())) conflict();
            id=request.policyId();
            version=latest+1;
        }
        var prepared=new ArrayList<PreparedRule>();
        for (var rule:request.rules()) {
            if (rule==null || rule.scopeId()==null || rule.connectionId()==null
                    || !allowed(rule.effect(),"ALLOW","DENY")
                    || !allowed(rule.pathMatch(),"SCOPE","EXACT","PREFIX")) invalid();
            var scope=scope(rule.scopeId(),true);
            access.requireConnectionRole(actor,scope.connectionId(),SecretRole.SECURITY);
            if (scope.connectionId()!=rule.connectionId() || !scope.available()
                    || !CONTENT_TYPES.contains(scope.contentType()) || !scope.contentType().equals(rule.contentType())) invalid();
            validateSupportedScope(scope);
            validateRule(actor,scope,rule);
            prepared.add(new PreparedRule(rule,scope));
        }
        jdbc.update("""
                INSERT INTO secret_storage_policies(policy_id,version,status,reason_code,evidence_ref,
                    created_by_user_id,valid_from,valid_until)
                VALUES (?,?,'DRAFT',?,?,?,?,?)
                """,id,version,request.reasonCode(),request.evidenceRef(),actor.userId(),request.validFrom(),request.validUntil());
        for (var item:prepared) {
            var r=item.request(); var s=item.scope();
            jdbc.update("""
                    INSERT INTO secret_storage_policy_rules(policy_id,policy_version,effect,connection_id,
                        scope_id,scope_revision,scope_fingerprint,content_type,branch_condition,path_match,protected_path_condition)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,id,version,r.effect(),s.connectionId(),s.id(),s.revision(),s.fingerprint(),s.contentType(),
                    r.branchCondition(),r.pathMatch(),r.protectedPathCondition());
        }
        rejectConflictingRules(repository.rules(id,version));
        repository.audit("POLICY_DRAFTED","POLICY",id,version,actor.userId());
        return summary(policy(id,version,false),actor,true);
    }

    @Transactional
    public PolicySummary approvePolicy(long policyId,long version,VersionRequest request,String login) {
        var actor=access.requirePrincipal(login);
        lockGovernance();
        var policy=policy(policyId,version,true);
        var rules=repository.rules(policyId,version);
        requireSecurityForPolicy(actor,rules);
        SecretCommandExecutor.requireExpectedVersion(request==null?null:request.expectedVersion(),policy.version());
        if (policy.creator()==actor.userId()) forbidden();
        if (!"DRAFT".equals(policy.status()) || policy.validUntil()!=null && !repository.now().isBefore(policy.validUntil())) conflict();
        for (var rule:rules) requireCurrentRule(rule);
        rejectConflictingRules(rules);
        // Serialize activation so two concurrent approvals cannot introduce an ambiguous rule set.
        var others=jdbc.query("""
                SELECT p.policy_id,p.version FROM secret_storage_policies p
                WHERE p.status='ACTIVE' AND p.policy_id<>?
                  AND (p.valid_until IS NULL OR p.valid_until>?) AND (?::timestamptz IS NULL OR p.valid_from<?)
                """,(rs,row)->new long[]{rs.getLong(1),rs.getLong(2)},policyId,policy.validFrom(),policy.validUntil(),policy.validUntil());
        for (var other:others) for (var left:rules) for (var right:repository.rules(other[0],other[1]))
            if (!left.effect().equals(right.effect()) && overlaps(left,right)) conflict();
        markPolicyRecheck(policyId);
        jdbc.update("UPDATE secret_storage_policies SET status='RETIRED',retired_at=now() WHERE policy_id=? AND status='ACTIVE'",policyId);
        jdbc.update("""
                UPDATE secret_storage_policies SET status='ACTIVE',approved_by_user_id=?,approved_at=now()
                WHERE policy_id=? AND version=? AND status='DRAFT'
                """,actor.userId(),policyId,version);
        repository.audit("POLICY_APPROVED","POLICY",policyId,version,actor.userId());
        return summary(policy(policyId,version,false),actor,true);
    }

    @Transactional
    public PolicySummary retire(long policyId,RetireRequest request,String login) {
        var actor=access.requirePrincipal(login);
        lockGovernance();
        if (request==null || request.expectedVersion()==null
                || !allowed(request.reasonCode(),"POLICY_WITHDRAWN","POLICY_REPLACED")) invalid();
        evidence(request.evidenceRef());
        var policy=policy(policyId,request.expectedVersion(),true);
        requireSecurityForPolicy(actor,repository.rules(policyId,policy.version()));
        if (policy.creator()==actor.userId()) forbidden();
        if (!"ACTIVE".equals(policy.status())) conflict();
        jdbc.update("UPDATE secret_storage_policies SET status='RETIRED',retired_at=now() WHERE policy_id=? AND version=?",policyId,policy.version());
        markPolicyRecheck(policyId);
        jdbc.update("""
                INSERT INTO secret_audit_events(event_type,actor_user_id,target_type,target_id,target_version,safe_changes)
                VALUES ('POLICY_RETIRED',?,'POLICY',?,?,jsonb_build_object('reasonCode',?::text,'evidenceRef',?::text))
                """,actor.userId(),policyId,policy.version(),request.reasonCode(),request.evidenceRef());
        return summary(policy(policyId,policy.version(),false),actor,true);
    }

    @Transactional
    public Classification propose(long scopeId,ProposalRequest request,String login) {
        var actor=access.requirePrincipal(login);
        lockGovernance();
        var scope=scope(scopeId,true);
        if (!access.hasConnectionRole(actor,scope.connectionId(),SecretRole.OPERATIONS)
                && !access.hasConnectionRole(actor,scope.connectionId(),SecretRole.SECURITY)) forbidden();
        if (request==null || !allowed(request.origin(),"TEST","PRODUCTION")
                || (request.storagePolicyId()==null)!=(request.storagePolicyVersion()==null)
                || !allowed(request.reasonCode(),"POLICY_PENDING","SOURCE_CLASSIFICATION","SOURCE_CORRECTION")) invalid();
        evidence(request.evidenceRef());
        SecretCommandExecutor.requireExpectedVersion(request.expectedScopeVersion(),scope.originVersion());
        if (!scope.available() || !SOURCE_TYPES.contains(scope.contentType())) conflict();
        validateSupportedScope(scope);
        preventFixtureMisclassification(scope,request.origin());
        if (request.storagePolicyId()==null && !"POLICY_PENDING".equals(request.reasonCode())) invalid();
        if (request.storagePolicyId()!=null && "POLICY_PENDING".equals(request.reasonCode())) invalid();
        if (request.storagePolicyId()!=null) applicablePolicy(request.storagePolicyId(),request.storagePolicyVersion(),scope);
        if (repository.pending(scopeId).isPresent()) conflict();
        jdbc.update("""
                INSERT INTO secret_scope_classification_proposals(scope_id,expected_scope_version,scope_revision,
                    scope_fingerprint,proposed_origin,policy_id,policy_version,reason_code,evidence_ref,
                    proposed_by_user_id,status)
                VALUES (?,?,?,?,?,?,?,?,?,?,'PENDING_APPROVAL')
                """,scopeId,scope.originVersion(),scope.revision(),scope.fingerprint(),request.origin(),
                request.storagePolicyId(),request.storagePolicyVersion(),request.reasonCode(),request.evidenceRef(),actor.userId());
        repository.audit("CLASSIFICATION_PROPOSED","SCOPE",scopeId,scope.originVersion(),actor.userId());
        return classification(scope,actor,true);
    }

    @Transactional
    public Classification approveProposal(long scopeId,long proposalId,ApproveProposalRequest request,String login) {
        var actor=access.requirePrincipal(login);
        lockGovernance();
        var scope=scope(scopeId,true);
        access.requireConnectionRole(actor,scope.connectionId(),SecretRole.SECURITY);
        var proposal=proposal(scopeId,proposalId,true);
        SecretCommandExecutor.requireExpectedVersion(request==null?null:request.expectedScopeVersion(),scope.originVersion());
        SecretCommandExecutor.requireExpectedVersion(request==null?null:request.expectedProposalVersion(),proposal.version());
        if (proposal.proposer()==actor.userId()) forbidden();
        if (!"PENDING_APPROVAL".equals(proposal.status()) || !scope.available()
                || proposal.expectedScopeVersion()!=scope.originVersion() || proposal.scopeRevision()!=scope.revision()
                || !proposal.fingerprint().equals(scope.fingerprint())) conflict();
        preventFixtureMisclassification(scope,proposal.origin());
        if (proposal.policyId()!=null) applicablePolicy(proposal.policyId(),proposal.policyVersion(),scope);
        if (proposal.reviewerUserId()!=null && proposal.reviewerUserId()!=actor.userId()) forbidden();
        return applyApprovedProposal(scope,proposal,actor);
    }

    Classification applyApprovedProposal(Scope scope,ProposalState proposal,SecretPrincipal actor) {
        long scopeId=scope.id();
        long proposalId=proposal.id();
        long next=nextDecisionVersion(scopeId);
        long decisionId=recordDecision(scope,proposal,"APPROVED",proposal.reason(),actor.userId(),next);
        jdbc.update("""
                UPDATE secret_connection_scopes SET response_origin=?,response_origin_version=?,
                    response_origin_set_by_user_id=?,response_origin_set_at=now(),updated_at=now()
                WHERE scope_id=? AND response_origin_version=?
                """,proposal.origin(),next,actor.userId(),scopeId,scope.originVersion());
        jdbc.update("UPDATE secret_scope_classification_proposals SET status='APPROVED',version=version+1 WHERE proposal_id=?",proposalId);
        jdbc.update("UPDATE secret_scope_policy_bindings SET effective_until=now() WHERE scope_id=? AND effective_until IS NULL",scopeId);
        if (proposal.policyId()!=null) jdbc.update("""
                INSERT INTO secret_scope_policy_bindings(scope_id,scope_revision,scope_origin_version,scope_fingerprint,
                    policy_id,policy_version,classification_decision_id) VALUES (?,?,?,?,?,?,?)
                """,scopeId,scope.revision(),next,scope.fingerprint(),proposal.policyId(),proposal.policyVersion(),decisionId);
        jdbc.update("""
                INSERT INTO secret_scope_classification_impacts(decision_id,occurrence_id,case_id,previous_origin,new_origin)
                SELECT ?,o.occurrence_id,c.case_id,?,? FROM secret_occurrences o
                LEFT JOIN secret_case_occurrences co ON co.occurrence_id=o.occurrence_id
                    AND EXISTS (SELECT 1 FROM secret_response_cases current_case WHERE current_case.case_id=co.case_id AND current_case.is_current)
                LEFT JOIN secret_response_cases c ON c.case_id=co.case_id AND c.is_current
                WHERE o.scope_id=?
                """,decisionId,scope.origin(),proposal.origin(),scopeId);
        // Acquire case reference locks before occurrence writes, matching the location-action order.
        jdbc.update("UPDATE secret_occurrences SET policy_recheck_required=true WHERE scope_id=? AND exposure_status<>'UNKNOWN'",scopeId);
        repository.audit("CLASSIFICATION_APPROVED","SCOPE",scopeId,next,actor.userId());
        snapshots.invalidateScope(scopeId);
        if (jdbc.queryForObject("SELECT to_regprocedure('secret_apply_storage_policy_defaults(bigint)')::text",String.class)!=null)
            jdbc.query("SELECT secret_apply_storage_policy_defaults(NULL::bigint)",(rs,row)->rs.getObject(1));
        // Reuse exact corrections before deciding whether a TEST Finding needs an investigation.
        if (jdbc.queryForObject("SELECT to_regprocedure('secret_reconcile_test_alerts(bigint)')::text",String.class)!=null)
            jdbc.query("SELECT secret_reconcile_test_alerts(NULL::bigint)",(rs,row)->rs.getObject(1));
        return classification(scope(scopeId,false),actor,true);
    }

    @Transactional
    public Classification rejectProposal(long scopeId,long proposalId,RejectProposalRequest request,String login) {
        var actor=access.requirePrincipal(login);
        lockGovernance();
        var scope=scope(scopeId,true);
        access.requireConnectionRole(actor,scope.connectionId(),SecretRole.SECURITY);
        var proposal=proposal(scopeId,proposalId,true);
        if (request==null || !allowed(request.reasonCode(),"INSUFFICIENT_EVIDENCE","WRONG_SCOPE","POLICY_MISMATCH")) invalid();
        SecretCommandExecutor.requireExpectedVersion(request.expectedProposalVersion(),proposal.version());
        if (!"PENDING_APPROVAL".equals(proposal.status())) conflict();
        long version=nextDecisionVersion(scopeId);
        recordDecision(scope,proposal,"REJECTED",request.reasonCode(),actor.userId(),version);
        jdbc.update("UPDATE secret_scope_classification_proposals SET status='REJECTED',version=version+1 WHERE proposal_id=?",proposalId);
        repository.audit("CLASSIFICATION_REJECTED","SCOPE",scopeId,version,actor.userId());
        return classification(scope,actor,true);
    }

    @Transactional(readOnly=true)
    public PolicyEvaluation evaluateOccurrence(long occurrenceId,String login) {
        var actor=access.requirePrincipal(login);
        access.requireOccurrenceRead(actor,occurrenceId);
        return jdbc.query("SELECT * FROM secret_occurrence_policy_results WHERE occurrence_id=?",
                (rs,row)->new PolicyEvaluation(rs.getLong("occurrence_id"),rs.getObject("binding_id",Long.class),
                rs.getObject("policy_id",Long.class),rs.getObject("policy_version",Long.class),rs.getString("policy_result"),
                rs.getString("reason_code"),rs.getBoolean("requires_reassessment")),occurrenceId).stream().findFirst()
                .orElseThrow(()->new ApiException(ErrorCode.NOT_FOUND));
    }

    private Classification classification(Scope scope,SecretPrincipal actor,boolean changed) {
        var pending=repository.pending(scope.id()).orElse(null);
        var history=repository.history(scope.id());
        var approved=repository.approvedDecision(scope.id(),scope.originVersion()).orElse(null);
        var binding=repository.binding(scope.id()).orElse(null);
        PolicySummary policy=binding==null?null:summary(policy(binding.policyId(),binding.policyVersion(),false),actor,false);
        String approval=approved!=null?"APPROVED":"UNCLASSIFIED".equals(scope.origin())?"UNCLASSIFIED":"LEGACY_REVIEW_REQUIRED";
        if (pending!=null) approval="PENDING_APPROVAL";
        var capabilities=classificationCapabilities(actor,scope,pending);
        return new Classification(scope.id(),scope.connectionId(),scope.safeName(),scope.contentType(),scope.revision(),
                scope.originVersion(),scope.origin(),scope.originVersion(),binding==null?null:binding.policyId(),
                binding==null?null:binding.policyVersion(),approval,policyStatus(scope,binding),approved==null?null:approved.actorUserId(),
                approved==null?null:approved.decidedAt(),policy,pending==null?null:new Proposal(pending.id(),scope.id(),
                pending.origin(),pending.policyId(),pending.policyVersion(),pending.reason(),pending.evidence(),
                pending.proposer(),pending.expectedScopeVersion(),pending.version(),pending.status(),pending.createdAt(),capabilities,
                pending.approvalMode(),pending.approvalRuleVersion(),pending.reviewerUserId()),
                history,capabilities,changed,repository.setupReasons(scope.id()),
                repository.reviewers(scope.connectionId(),pending==null?actor.userId():pending.proposer()),null);
    }

    private ClassificationCapabilities classificationCapabilities(SecretPrincipal actor,Scope scope,ProposalState pending) {
        boolean security=access.hasConnectionRole(actor,scope.connectionId(),SecretRole.SECURITY);
        boolean current=pending!=null && pending.expectedScopeVersion()==scope.originVersion()
                && pending.scopeRevision()==scope.revision() && pending.fingerprint().equals(scope.fingerprint());
        if (current && pending.policyId()!=null) current=policy(pending.policyId(),pending.policyVersion(),false).usable(repository.now());
        return new ClassificationCapabilities(scope.available() && SOURCE_TYPES.contains(scope.contentType()) && pending==null
                && (security || access.hasConnectionRole(actor,scope.connectionId(),SecretRole.OPERATIONS)),
                scope.available() && security && current && pending.proposer()!=actor.userId()
                    && (pending.reviewerUserId()==null || pending.reviewerUserId()==actor.userId()),
                security && pending!=null,scope.available() && security && CONTENT_TYPES.contains(scope.contentType()),
                pending!=null && scope.available() && (security || pending.proposer()==actor.userId() && access.hasConnectionRole(actor,scope.connectionId(),SecretRole.OPERATIONS)));
    }

    private PolicySummary summary(Policy policy,SecretPrincipal actor,boolean changed) {
        var rules=repository.rules(policy.id(),policy.version());
        boolean security=!rules.isEmpty() && rules.stream().allMatch(r->access.hasConnectionRole(actor,r.connectionId(),SecretRole.SECURITY));
        boolean independent=policy.creator()!=actor.userId();
        boolean hasDraft=Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS(SELECT 1 FROM secret_storage_policies WHERE policy_id=? AND status='DRAFT')",Boolean.class,policy.id()));
        return new PolicySummary(policy.id(),policy.version(),policy.status(),policy.reason(),policy.evidence(),policy.creator(),
                policy.approver(),policy.createdAt(),policy.validFrom(),policy.validUntil(),policy.approvedAt(),policy.retiredAt(),
                policy.usable(repository.now()),rules.stream().filter(r->access.hasConnectionRole(actor,r.connectionId(),SecretRole.SECURITY)
                        || access.hasConnectionRole(actor,r.connectionId(),SecretRole.OPERATIONS)).map(Rule::safe).toList(),new PolicyCapabilities(
                security && independent && "DRAFT".equals(policy.status()) && (policy.validUntil()==null || repository.now().isBefore(policy.validUntil())),
                security && independent && "ACTIVE".equals(policy.status()),security && !hasDraft),changed);
    }

    private void validateRule(SecretPrincipal actor,Scope scope,RuleRequest rule) {
        if ("SCOPE".equals(rule.pathMatch())) {
            if (rule.protectedPathCondition()!=null || rule.branchCondition()!=null) invalid();
            return;
        }
        access.requireConnectionRole(actor,scope.connectionId(),SecretRole.OPERATIONS);
        var github=GITHUB.matcher(scope.approvedRef());
        if (!"GITHUB_REPOSITORY_FILES".equals(scope.contentType()) || !github.matches()
                || !Objects.equals(rule.branchCondition(),github.group(3))) invalid();
        String path=rule.protectedPathCondition();
        if (path==null || path.isBlank() || path.length()>500 || !path.equals(path.trim())
                || path.startsWith("/") || path.contains("\\") || path.contains("..") || path.contains("%")
                || path.contains("?") || path.contains("#") || path.contains(":") || path.contains("*")
                || path.chars().anyMatch(c->c<32 || c==127) || SENSITIVE_VALUE.matcher(path).matches()
                || !path.startsWith(github.group(4)) || "PREFIX".equals(rule.pathMatch()) && !path.endsWith("/")) invalid();
    }

    void validateSupportedScope(Scope scope) {
        if ("GITHUB_REPOSITORY_FILES".equals(scope.contentType())) {
            if (!"CURRENT_COMMIT_ONLY".equals(scope.historyLimit()) || !GITHUB.matcher(scope.approvedRef()).matches()
                    || scope.approvedRef().contains("..") || scope.approvedRef().contains("\\")) conflict();
        } else if (!Boolean.TRUE.equals(jdbc.queryForObject("SELECT "
                +com.logssey.secret.run.AwsScopeSql.predicate("s")+" FROM secret_connection_scopes s WHERE scope_id=?",
                Boolean.class,scope.id()))) conflict();
    }

    private void requireCurrentRule(Rule rule) {
        var scope=scope(rule.scopeId(),true);
        if (!scope.available() || scope.revision()!=rule.scopeRevision() || !scope.fingerprint().equals(rule.fingerprint())) conflict();
    }
    private void rejectConflictingRules(List<Rule> rules) {
        for (int i=0;i<rules.size();i++) for (int j=i+1;j<rules.size();j++)
            if (!rules.get(i).effect().equals(rules.get(j).effect()) && overlaps(rules.get(i),rules.get(j))) conflict();
    }
    private boolean overlaps(Rule a,Rule b) {
        if (a.scopeId()!=b.scopeId() || !a.contentType().equals(b.contentType()) || a.scopeRevision()!=b.scopeRevision()) return false;
        if ("SCOPE".equals(a.pathMatch()) || "SCOPE".equals(b.pathMatch())) return true;
        if (!Objects.equals(a.branch(),b.branch())) return false;
        if ("EXACT".equals(a.pathMatch()) && "EXACT".equals(b.pathMatch())) return a.protectedPath().equals(b.protectedPath());
        if ("PREFIX".equals(a.pathMatch()) && b.protectedPath().startsWith(a.protectedPath())) return true;
        return "PREFIX".equals(b.pathMatch()) && a.protectedPath().startsWith(b.protectedPath());
    }
    private void applicablePolicy(long id,long version,Scope scope) {
        var policy=policy(id,version,true);
        if (!policy.usable(repository.now()) || repository.rules(id,version).stream().noneMatch(r->r.scopeId()==scope.id()
                && r.scopeRevision()==scope.revision() && r.fingerprint().equals(scope.fingerprint())
                && r.contentType().equals(scope.contentType()))) conflict();
    }
    private void markPolicyRecheck(long id) {
        jdbc.update("""
                UPDATE secret_occurrences o SET policy_recheck_required=true
                WHERE o.exposure_status<>'UNKNOWN' AND EXISTS (SELECT 1 FROM secret_scope_policy_bindings b
                    WHERE b.scope_id=o.scope_id AND b.policy_id=? AND b.effective_until IS NULL)
                """,id);
        jdbc.query("SELECT scope_id FROM secret_scope_policy_bindings WHERE policy_id=? AND effective_until IS NULL",
                (rs,row)->rs.getLong(1),id).forEach(snapshots::invalidateScope);
    }
    private long recordDecision(Scope scope,ProposalState proposal,String decision,String reason,long actor,long version) {
        return jdbc.queryForObject("""
                INSERT INTO secret_scope_origin_decisions(scope_id,from_origin,to_origin,reason_code,actor_user_id,
                    version,proposal_id,evidence_ref,decision,approval_mode,approval_rule_version) VALUES (?,?,?,?,?,?,?,?,?,?,?) RETURNING decision_id
                """,Long.class,scope.id(),scope.origin(),proposal.origin(),reason,actor,version,proposal.id(),proposal.evidence(),decision,proposal.approvalMode(),proposal.approvalRuleVersion());
    }
    private long nextDecisionVersion(long scopeId) {
        return jdbc.queryForObject("SELECT COALESCE(MAX(version),0)+1 FROM secret_scope_origin_decisions WHERE scope_id=?",Long.class,scopeId);
    }
    private long latestVersion(long id) {
        Long latest=jdbc.queryForObject("SELECT MAX(version) FROM secret_storage_policies WHERE policy_id=?",Long.class,id);
        if (latest==null) notFound();
        return latest;
    }
    void preventFixtureMisclassification(Scope scope,String origin) {
        var match=GITHUB.matcher(scope.approvedRef());
        if (match.matches() && "Logssey".equalsIgnoreCase(match.group(1)) && "test-find-key".equalsIgnoreCase(match.group(2))
                && "PRODUCTION".equals(origin)) conflict();
    }
    void lockGovernance() { jdbc.queryForObject("SELECT pg_advisory_xact_lock(?)",Object.class,6197611306L); }
    private SecretPrincipal reader(String login) {
        var actor=access.requirePrincipal(login);
        if (!access.hasAnyRole(actor,READ_ROLES)) forbidden();
        return actor;
    }
    private boolean canReadScope(SecretPrincipal actor,Scope scope) {
        return access.hasConnectionRole(actor,scope.connectionId(),SecretRole.SECURITY)
                || access.hasConnectionRole(actor,scope.connectionId(),SecretRole.OPERATIONS);
    }
    private void requireReadScope(SecretPrincipal actor,Scope scope) { if (!canReadScope(actor,scope)) notFound(); }
    private boolean canReadPolicy(SecretPrincipal actor,List<Rule> rules) {
        return !rules.isEmpty() && rules.stream().allMatch(r->access.hasConnectionRole(actor,r.connectionId(),SecretRole.SECURITY)
                || access.hasConnectionRole(actor,r.connectionId(),SecretRole.OPERATIONS));
    }
    private void requireSecurityForPolicy(SecretPrincipal actor,List<Rule> rules) {
        if (rules.isEmpty()) notFound();
        for (var rule:rules) access.requireConnectionRole(actor,rule.connectionId(),SecretRole.SECURITY);
    }
    private boolean needsReview(Scope scope) { return !repository.setupReasons(scope.id()).isEmpty(); }
    private String policyStatus(Scope scope,Binding binding) {
        if (!CONTENT_TYPES.contains(scope.contentType())) return "NOT_APPLICABLE";
        if (binding==null) return "POLICY_PENDING";
        var policy=policy(binding.policyId(),binding.policyVersion(),false);
        if (!"ACTIVE".equals(policy.status())) return "RETIRED";
        var now=repository.now();
        if (now.isBefore(policy.validFrom())) return "NOT_YET_VALID";
        if (policy.validUntil()!=null && !now.isBefore(policy.validUntil())) return "EXPIRED";
        if (repository.rules(policy.id(),policy.version()).stream().noneMatch(r->r.scopeId()==scope.id()
                && r.scopeRevision()==scope.revision() && r.fingerprint().equals(scope.fingerprint()))) return "SCOPE_CHANGED";
        return "ACTIVE";
    }
    private Scope scope(long id,boolean lock) { return repository.scope(id,lock).orElseThrow(()->new ApiException(ErrorCode.NOT_FOUND)); }
    private Policy policy(long id,long version,boolean lock) { return repository.policy(id,version,lock).orElseThrow(()->new ApiException(ErrorCode.NOT_FOUND)); }
    private ProposalState proposal(long scope,long id,boolean lock) { return repository.proposal(scope,id,lock).orElseThrow(()->new ApiException(ErrorCode.NOT_FOUND)); }
    private static boolean allowed(String value,String... values) { return value!=null && java.util.Arrays.asList(values).contains(value); }
    private static void pagination(int page,int size) { if (page<0 || page>1_000_000 || size<1 || size>100) invalid(); }
    private static void evidence(String ref) { if (ref==null || !EVIDENCE.matcher(ref).matches()) invalid(); }
    private static void invalid() { throw new ApiException(ErrorCode.INVALID_INPUT); }
    private static void conflict() { throw new ApiException(ErrorCode.CONFLICT); }
    private static void forbidden() { throw new ApiException(ErrorCode.FORBIDDEN); }
    private static void notFound() { throw new ApiException(ErrorCode.NOT_FOUND); }
    private record PreparedRule(RuleRequest request,Scope scope) { }
}
