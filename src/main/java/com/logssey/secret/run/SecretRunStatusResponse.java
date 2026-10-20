package com.logssey.secret.run;

import java.time.OffsetDateTime;
import java.util.List;

public record SecretRunStatusResponse(long runId,
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
        List<SecretRunScopeResultResponse> scopeResults,
        @com.fasterxml.jackson.annotation.JsonUnwrapped SecretRunCoverageResponse coverage) {
    @com.fasterxml.jackson.annotation.JsonProperty("provider")
    public String provider() { return coverage==null?null:coverage.provider(); }

    public SecretRunStatusResponse(long runId,
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
        this(runId, connectionId, triggerType, status, collectionStatus, detectionStatus, validationStatus, scopeCount, completedScopeCount, incompleteScopeCount, collectedObjectCount, attemptNo, maxAttempts, requestedAt, startedAt, finishedAt, availableAt, failureCode, scopeResults, null);
    }
}
