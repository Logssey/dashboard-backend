package com.logssey.secret.query;

import java.time.OffsetDateTime;

public record SecretSummaryResponse(
        long id,
        String issuer,
        String credentialType,
        String componentState,
        String maskedLabel,
        String severity,
        String validationStatus,
        String validationReasonCode,
        OffsetDateTime validatedAt,
        OffsetDateTime validationCheckedAt,
        long occurrenceCount,
        OffsetDateTime firstSeenAt,
        OffsetDateTime lastSeenAt) {
}
