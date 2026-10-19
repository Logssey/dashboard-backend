package com.logssey.secret.response;

import java.time.OffsetDateTime;

public record SecretCaseReview(long reviewId, String decision, String reasonCode,
                               long reviewedByUserId, String reviewedByName,
                               OffsetDateTime reviewedAt, long caseVersion) {
}
