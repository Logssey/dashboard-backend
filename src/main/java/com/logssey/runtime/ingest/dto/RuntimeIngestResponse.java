package com.logssey.runtime.ingest.dto;

public record RuntimeIngestResponse(
        long rawEventId,
        Long runtimeEventId,
        Long findingId,
        boolean accepted,
        boolean duplicate,
        String processingStatus,
        String receivedAt) {
}
