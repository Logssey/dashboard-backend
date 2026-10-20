package com.logssey.secret.decision;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

/** Controlled decision contracts. Evidence contains internal references, never source content. */
public final class SecretDecisionContracts {
    private SecretDecisionContracts() { }
    public record DecisionRequest(String decision,String reasonCode,Long findingId,List<String> evidenceRefs,
        Long expectedOccurrenceVersion,Long expectedScopeVersion,Long expectedPolicyVersion,String idempotencyKey,
        String missingReasonCode,Long followUpOwnerUserId,OffsetDateTime dueAt,String evidenceRef) { }
    public record LinkRequest(Long decisionId,Long expectedDecisionVersion,Long expectedOccurrenceVersion,
        Long expectedScopeVersion,String idempotencyKey) { }
    public record DecisionResult(long decisionId,long occurrenceId,String exposureStatus,Long caseId,
        String caseOperation,Long caseVersion,Long investigationTaskId,Long correctionId,String queueBucket,
        boolean requiresSnapshotRefresh) { }
    public record Finding(long findingId,String ruleId,String ruleVersion,OffsetDateTime detectedAt,boolean valid) { }
    public record StoragePolicy(String result,Long policyId,Long version,Long bindingId,String reasonCode,
        boolean requiresReassessment) { }
    public record Validity(String result,String reasonCode,OffsetDateTime observedAt) { }
    public record Versions(long occurrence,long scope,Long policy) { }
    public record Assignee(long userId,String displayName) { }
    public record CaseLinkData(Long caseId,Long caseVersion,String caseOrigin,String caseLinkStatus,
        boolean canRepair,Long decisionId,Long decisionVersion) { }
    public record Correction(long correctionId,long findingId,long decisionId,String source,OffsetDateTime expiresAt,
        boolean currentlyApplicable,String recheckReason) { }
    public record ReviewContext(long credentialSetId,long occurrenceId,long connectionId,long scopeId,
        long scopeRevision,String origin,String componentState,String presence,String exposureStatus,
        String maskedLabel,String issuer,String credentialType,String safeLocationLabel,List<Finding> findings,
        StoragePolicy storagePolicy,Validity validity,Versions versions,List<String> allowedDecisions,
        Map<String,List<String>> allowedReasonCodes,List<String> allowedMissingReasonCodes,
        List<Assignee> eligibleInvestigationAssignees,CaseLinkData caseLinkData,List<Correction> corrections,
        Map<String,String> decisionUnavailableReasons) { }
    public record QueueItem(long credentialSetId,long occurrenceId,Long caseId,String origin,String maskedLabel,
        String componentState,String presence,String exposureStatus,String whyHere,String nextAction) { }
    public record QueuePage(List<QueueItem> items,long total,int page,int size,String unit,OffsetDateTime asOf,
        boolean partialCoverage,boolean restrictedCoverage) { }
}
