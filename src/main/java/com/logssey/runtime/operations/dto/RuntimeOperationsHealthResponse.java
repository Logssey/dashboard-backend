package com.logssey.runtime.operations.dto;

public record RuntimeOperationsHealthResponse(
        String status,
        EventWindow eventWindow,
        Retention retention,
        LastMaintenance lastMaintenance,
        String generatedAt) {

    public record EventWindow(
            int minutes,
            long received,
            long grouped,
            long suppressed,
            long rateLimited,
            long ignored,
            long failed) {
    }

    public record Retention(long payloadBacklog, String oldestDueAt) {
    }

    public record LastMaintenance(
            String completedAt,
            long payloadsPurged,
            long rateWindowsDeleted,
            long remainingPayloadBacklog) {
    }
}
