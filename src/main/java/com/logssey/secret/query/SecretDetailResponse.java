package com.logssey.secret.query;

import java.time.OffsetDateTime;
import java.util.List;

public record SecretDetailResponse(
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
        OffsetDateTime lastSeenAt,
        String expiryPolicy,
        OffsetDateTime expiresAt,
        String lifecycleStatus,
        List<SecretOccurrenceResponse> occurrences) {
}
