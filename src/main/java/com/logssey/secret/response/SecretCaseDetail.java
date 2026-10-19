package com.logssey.secret.response;

import java.time.OffsetDateTime;
import java.util.List;

public record SecretCaseDetail(long caseId, long secretId, String maskedLabel, String issuer,
                               String credentialType, String caseOrigin, String stage, String assigneeTeam,
                               Long assigneeUserId, String assigneeDisplayName, long version,
                               OffsetDateTime createdAt, OffsetDateTime updatedAt,
                               long openingOccurrenceId, String openingReason,
                               List<SecretAssignmentHistory> assignmentHistory,
                               List<SecretCaseOccurrence> occurrences,
                               String reviewStatus, List<SecretCaseReview> reviews,
                               List<SecretChecklistItem> checklist,
                               List<SecretChecklistChange> checklistHistory,
                               List<SecretActionRecord> actions,
                               List<SecretCaseStageChange> stageHistory,
                               SecretCaseCapabilities capabilities) {
    static SecretCaseDetail from(SecretCaseSummary summary, SecretCaseRepository.OpeningEvidence evidence,
                                 List<SecretAssignmentHistory> history,
                                 List<SecretCaseOccurrence> occurrences, String reviewStatus,
                                 List<SecretCaseReview> reviews, List<SecretChecklistItem> checklist,
                                 List<SecretChecklistChange> checklistHistory,
                                 List<SecretActionRecord> actions,
                                 List<SecretCaseStageChange> stageHistory,
                                 SecretCaseCapabilities capabilities) {
        return new SecretCaseDetail(summary.caseId(), summary.secretId(), summary.maskedLabel(),
                summary.issuer(), summary.credentialType(), summary.caseOrigin(), summary.stage(),
                summary.assigneeTeam(),
                summary.assigneeUserId(), summary.assigneeDisplayName(), summary.version(),
                summary.createdAt(), summary.updatedAt(), evidence.occurrenceId(),
                evidence.reason(), history, occurrences, reviewStatus, reviews, checklist,
                checklistHistory, actions, stageHistory,
                capabilities);
    }
}
