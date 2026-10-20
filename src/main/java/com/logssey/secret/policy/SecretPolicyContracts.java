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
                                  String reasonCode, String evidenceRef, Long expectedScopeVersion) { }
    public record ApproveProposalRequest(Long expectedScopeVersion, Long expectedProposalVersion) { }
    public record RejectProposalRequest(String reasonCode, Long expectedProposalVersion) { }
    public record SafeRule(long ruleId, long connectionId, long scopeId, String contentType,
                           String effect, String pathMatch) { }
    public record PolicyCapabilities(boolean canApprove, boolean canRetire, boolean canCreateVersion) { }
    public record PolicySummary(long policyId, long version, String status, String reasonCode, String evidenceRef,
                                 long createdByUserId, Long approvedByUserId, OffsetDateTime createdAt,
                                 OffsetDateTime validFrom, OffsetDateTime validUntil, OffsetDateTime approvedAt,
                                 OffsetDateTime retiredAt, boolean usableNow, List<SafeRule> rules,
                                 PolicyCapabilities capabilities, boolean requiresSnapshotRefresh) { }
    public record ClassificationCapabilities(boolean canPropose, boolean canApprove, boolean canReject,
                                             boolean canDraftPolicy) { }
    public record Proposal(long proposalId, long scopeId, String origin, Long storagePolicyId,
                            Long storagePolicyVersion, String reasonCode, String evidenceRef,
                            long proposedByUserId, long expectedScopeVersion, long version,
                            String status, OffsetDateTime createdAt, ClassificationCapabilities capabilities) { }
    public record OriginDecision(long decisionId, Long proposalId, String decision, String fromOrigin,
                                  String toOrigin, String reasonCode, String evidenceRef, long actorUserId,
                                  OffsetDateTime decidedAt, long version) { }
    public record Classification(long scopeId, long connectionId, String displayName, String contentType,
                                   long scopeRevision, long scopeVersion, String origin, long originVersion,
                                   Long storagePolicyId, Long storagePolicyVersion, String approvalStatus,
                                   String policyStatus,
                                   Long approvedByUserId, OffsetDateTime approvedAt, PolicySummary storagePolicy,
                                   Proposal pendingProposal, List<OriginDecision> history,
                                   ClassificationCapabilities capabilities, boolean requiresSnapshotRefresh) { }
    public record PolicyEvaluation(long occurrenceId, Long bindingId, Long policyId, Long policyVersion,
                                    String policyResult, String reasonCode, boolean requiresReassessment) { }
}
