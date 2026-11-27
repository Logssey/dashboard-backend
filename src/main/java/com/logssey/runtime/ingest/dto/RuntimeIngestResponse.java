package com.logssey.runtime.ingest.dto;

public record RuntimeIngestResponse(
        Long rawEventId,
        Long runtimeEventId,
        Long findingId,
        boolean accepted,
        boolean duplicate,
        String processingStatus,
        String receivedAt) {
}
