package com.logssey.secret.query;

import java.time.OffsetDateTime;

public record SecretOccurrenceResponse(
        long id,
        long connectionId,
        String sourceObjectRef,
        String locationKey,
        String environment,
        String exposureStatus,
        String exposureRange,
        String presenceStatus,
        OffsetDateTime firstSeenAt,
        OffsetDateTime lastSeenAt) {
}
