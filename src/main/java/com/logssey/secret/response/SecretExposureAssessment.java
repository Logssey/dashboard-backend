package com.logssey.secret.response;

import java.time.OffsetDateTime;

public record SecretExposureAssessment(Long assessmentId, String fromStatus, String decision,
                                       String reasonCode, Long findingId, String findingRuleId,
                                       Long actorUserId, OffsetDateTime assessedAt, Long version) {
}
