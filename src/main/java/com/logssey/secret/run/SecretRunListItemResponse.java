package com.logssey.secret.run;

import java.time.OffsetDateTime;

/** Run summary only. Source identifiers, authentication references and values stay server-side. */
public record SecretRunListItemResponse(
        long runId,
        long connectionId,
        String provider,
        String displayName,
        String triggerType,
        String status,
        String collectionStatus,
        String detectionStatus,
        String validationStatus,
        long scopeCount,
        long completedScopeCount,
        long incompleteScopeCount,
        long collectedObjectCount,
        OffsetDateTime requestedAt,
        OffsetDateTime startedAt,
        OffsetDateTime finishedAt,
        String failureCode) {
}
