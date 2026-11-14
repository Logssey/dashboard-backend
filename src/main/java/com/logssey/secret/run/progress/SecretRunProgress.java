package com.logssey.secret.run.progress;

import java.time.OffsetDateTime;
import java.util.List;

public record SecretRunProgress(
        long runId, long connectionId, String provider, String status, int attemptNo, int maxAttempts,
        OffsetDateTime requestedAt, OffsetDateTime startedAt, OffsetDateTime finishedAt,
        OffsetDateTime availableAt, long scopeCount, long finishedScopeCount,
        Long collectedObjectCount, Long findingCount, Capabilities capabilities,
        OffsetDateTime capturedAt, OffsetDateTime latestActivityAt, int pollAfterMs,
        String eventsStatus, boolean historyComplete, boolean truncated, long suppressedEventCount,
        OffsetDateTime recordedFrom, OffsetDateTime expiredAt,
        List<Stage> stages, List<Event> events, long nextAfterEventId, boolean hasMore,
        ValidationSummary validationSummary) {
    public record Capabilities(boolean canViewFindings) {}
    public record Stage(String key, String status, OffsetDateTime startedAt,
                        OffsetDateTime finishedAt, String reasonCode,
                        Long processedCount, Long totalCount, String unit) {}
    public record Event(long id, int attemptNo, String stage, String operationCode, String outcome,
                        Integer httpStatus, String reasonCode, Long processedCount, Long totalCount,
                        Long durationMs, OffsetDateTime observedAt) {}
    public record ValidationSummary(boolean reuseRecorded, long newRequestCount,
                                    long completedRequestCount, Long reusedResultCount,
                                    long uncheckedCount, long incompleteCount, long unknownCount,
                                    List<ReusedResult> reusedResults, boolean reusedResultsTruncated) {}
    public record ReusedResult(String issuer, String result, String reasonCode,
                               OffsetDateTime providerCheckedAt, long sourceRunId, long count) {}
}
