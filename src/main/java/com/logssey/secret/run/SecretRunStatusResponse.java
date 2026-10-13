package com.logssey.secret.run;

import java.time.OffsetDateTime;
import java.util.List;

public record SecretRunStatusResponse(
        long runId,
        long connectionId,
        String triggerType,
        String status,
        String collectionStatus,
        String detectionStatus,
        String validationStatus,
        long scopeCount,
        long completedScopeCount,
        long incompleteScopeCount,
        long collectedObjectCount,
        int attemptNo,
        int maxAttempts,
        OffsetDateTime requestedAt,
        OffsetDateTime startedAt,
        OffsetDateTime finishedAt,
        OffsetDateTime availableAt,
        String failureCode,
        List<SecretRunScopeResultResponse> scopeResults) {
}
