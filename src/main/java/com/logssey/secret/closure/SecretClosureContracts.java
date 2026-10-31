package com.logssey.secret.closure;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

/** Public closure facts contain controlled codes and authorized internal identifiers only. */
public final class SecretClosureContracts {
    private SecretClosureContracts() { }
    public record ResolutionRequest(String decision,Long expectedCaseVersion,String closureCheckVersion,
        List<Long> evidenceIds,String coverageLevel,String idempotencyKey) { }
    public record DismissalRequest(String reasonCode,List<Long> evidenceIds,Long expectedCaseVersion,String idempotencyKey) { }
    public record ExceptionRequest(List<Long> occurrenceIds,String reasonCode,String evidenceRef,OffsetDateTime expiresAt,
        Long expectedCaseVersion,String idempotencyKey) { }
    public record RevokeRequest(Long exceptionId,String reasonCode,Long expectedCaseVersion,String idempotencyKey) { }
    public record TransferRequest(List<Long> occurrenceIds,String reasonCode,String evidenceRef,String acceptedTransferRef,
        Long expectedCaseVersion,String idempotencyKey) { }
    public record TransferReview(String decision,String reasonCode,Long expectedEvidenceVersion,Long expectedCaseVersion,
        String idempotencyKey) { }
    public record Check(String code,String status,String reasonCode,Long occurrenceId,List<Long> evidenceIds) { }
    public record Location(long occurrenceId,String safeLocationLabel,String status,String reasonCode) { }
    public record LocationGroup(String unit,List<Location> items,long visibleCount) { }
    public record CoverageOption(String level,List<String> limitations,List<Long> evidenceIds) { }
    public record EvidenceReference(long evidenceId,String reasonCode,String label,OffsetDateTime observedAt) { }
    public record LastResolution(long resolutionId,String coverageLevel,OffsetDateTime decidedAt,List<Long> evidenceIds,
        List<String> limitations) { }
    public record LastDismissal(long dismissalId,String reasonCode,OffsetDateTime decidedAt,List<Long> evidenceIds) { }
    public record Capabilities(boolean canResolve,boolean canApproveException,boolean canDismiss) { }
    public record ClosureChecks(long caseId,Long caseVersion,String targetOrigin,String closureCheckVersion,
        OffsetDateTime checkedAt,boolean restrictedCoverage,boolean canResolve,List<String> allowedCoverageLevels,
        List<CoverageOption> coverageOptions,List<Check> closureChecks,LocationGroup requiredResponseLocations,
        LocationGroup unlinkedAbnormalLocations,LocationGroup unassessedCurrentLocations,LocationGroup authorizedStorageLocations,
        LocationGroup historicalMissingLocations,String otherOriginNotice,Capabilities capabilities,
        List<String> allowedDismissalReasonCodes,List<Long> eligibleDismissalEvidenceIds,
        Map<String,List<EvidenceReference>> eligibleDismissalEvidenceByReason,LastResolution lastResolution,LastDismissal lastDismissal) { }
    public record Mutation(long caseId,long version,String status,Long resolutionId,String coverageLevel,
        Long dismissalId,Long exceptionId,Long evidenceId,boolean requiresSnapshotRefresh) { }
    public record ExceptionItem(long exceptionId,String reasonCode,String evidenceRef,long approvedByUserId,
        OffsetDateTime approvedAt,OffsetDateTime expiresAt,OffsetDateTime revokedAt,String status,List<Long> occurrenceIds,
        boolean currentlyApplicable,boolean canRevoke) { }
    public record Exceptions(long caseId,Long caseVersion,List<ExceptionItem> items,boolean canApprove,
        List<String> allowedReasonCodes,List<String> allowedRevokeReasonCodes,List<Location> eligibleOccurrences,int maxDurationDays,
        boolean fullyRiskAccepted,boolean restrictedCoverage) { }
    public record TransferEvidence(long evidenceId,long version,String reasonCode,String evidenceRef,String acceptedTransferRef,
        List<Long> occurrenceIds,long submittedByUserId,OffsetDateTime submittedAt,String status,Long reviewedByUserId,
        boolean canReview) { }
    public record TransferList(long caseId,Long caseVersion,List<TransferEvidence> items,boolean canSubmit,
        List<String> allowedReasonCodes,Map<String,List<String>> allowedReviewReasonCodes) { }
}
