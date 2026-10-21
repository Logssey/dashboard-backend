package com.logssey.secret.policy;

import java.time.OffsetDateTime;
import java.util.List;

/** Public policy DTOs contain controlled references and IDs, never approved source references or paths. */
public final class SecretPolicyContracts {
    private SecretPolicyContracts() { }

    public record Page<T>(List<T> items, long total, int page, int size) { }
    public record RuleRequest(Long connectionId, Long scopeId, String contentType, String effect,
                              String pathMatch, String branchCondition, String protectedPathCondition) {
        @Override public String toString() { return "RuleRequest[protected conditions omitted]"; }
    }
    public record DraftRequest(Long policyId, Long expectedVersion, String reasonCode, String evidenceRef,
                               OffsetDateTime validFrom, OffsetDateTime validUntil, List<RuleRequest> rules) { }
    public record VersionRequest(Long expectedVersion) { }
    public record RetireRequest(Long expectedVersion, String reasonCode, String evidenceRef) { }
    public record ProposalRequest(String origin, Long storagePolicyId, Long storagePolicyVersion,
                                  String reasonCode, String evidenceRef, Long expectedScopeVersion,
                                  String expectedApprovalMode, Long reviewerUserId, String idempotencyKey) {
        public ProposalRequest(String origin, Long policyId, Long policyVersion, String reason, String evidence, Long version) {
            this(origin,policyId,policyVersion,reason,evidence,version,null,null,null);
        }
    }
    public record PreviewRequest(String origin, Long storagePolicyId, Long storagePolicyVersion, Long expectedScopeVersion) { }
    public record Reviewer(long userId, String displayName) { }
    public record Preview(String approvalMode, List<String> approvalReasonCodes, String approvalRuleVersion,
                          List<Reviewer> eligibleReviewers, boolean canSubmit, List<String> remainingReasonCodes) { }
    public record ReviewAssignmentRequest(Long reviewerUserId, Long expectedProposalVersion, String idempotencyKey) { }
    public record ChangeResult(String effect, Long proposalId, Long decisionId, String approvalMode,
                               List<String> remainingReasonCodes) { }
    public record ApproveProposalRequest(Long expectedScopeVersion, Long expectedProposalVersion, String idempotencyKey) {
        public ApproveProposalRequest(Long scopeVersion, Long proposalVersion) { this(scopeVersion,proposalVersion,null); }
    }
    public record RejectProposalRequest(String reasonCode, Long expectedProposalVersion, String idempotencyKey) {
        public RejectProposalRequest(String reason, Long version) { this(reason,version,null); }
    }
    public record SafeRule(long ruleId, long connectionId, long scopeId, String contentType,
                           String effect, String pathMatch) { }
    public record PolicyCapabilities(boolean canApprove, boolean canRetire, boolean canCreateVersion) { }
    public record PolicySummary(long policyId, long version, String status, String reasonCode, String evidenceRef,
                                 long createdByUserId, Long approvedByUserId, OffsetDateTime createdAt,
                                 OffsetDateTime validFrom, OffsetDateTime validUntil, OffsetDateTime approvedAt,
                                 OffsetDateTime retiredAt, boolean usableNow, List<SafeRule> rules,
                                 PolicyCapabilities capabilities, boolean requiresSnapshotRefresh) { }
    public record ClassificationCapabilities(boolean canPropose, boolean canApprove, boolean canReject,
                                             boolean canDraftPolicy, boolean canAssignReviewer) { }
    public record Proposal(long proposalId, long scopeId, String origin, Long storagePolicyId,
                            Long storagePolicyVersion, String reasonCode, String evidenceRef,
                            long proposedByUserId, long expectedScopeVersion, long version,
                            String status, OffsetDateTime createdAt, ClassificationCapabilities capabilities,
                            String approvalMode, String approvalRuleVersion, Long reviewerUserId) { }
    public record OriginDecision(long decisionId, Long proposalId, String decision, String fromOrigin,
                                  String toOrigin, String reasonCode, String evidenceRef, long actorUserId,
                                  OffsetDateTime decidedAt, long version, String approvalMode, String approvalRuleVersion) { }
    public record Classification(long scopeId, long connectionId, String displayName, String contentType,
                                   long scopeRevision, long scopeVersion, String origin, long originVersion,
                                   Long storagePolicyId, Long storagePolicyVersion, String approvalStatus,
                                   String policyStatus,
                                   Long approvedByUserId, OffsetDateTime approvedAt, PolicySummary storagePolicy,
                                   Proposal pendingProposal, List<OriginDecision> history,
                                   ClassificationCapabilities capabilities, boolean requiresSnapshotRefresh,
                                   List<String> setupReasonCodes, List<Reviewer> eligibleReviewers, ChangeResult changeResult) {
        public Classification withChange(ChangeResult result) {
            return new Classification(scopeId,connectionId,displayName,contentType,scopeRevision,scopeVersion,origin,originVersion,
                storagePolicyId,storagePolicyVersion,approvalStatus,policyStatus,approvedByUserId,approvedAt,storagePolicy,
                pendingProposal,history,capabilities,!"UNCHANGED".equals(result.effect()),setupReasonCodes,eligibleReviewers,result);
        }
    }
    public record PolicyEvaluation(long occurrenceId, Long bindingId, Long policyId, Long policyVersion,
                                    String policyResult, String reasonCode, boolean requiresReassessment) { }
}
