package com.logssey.runtime.operations.dto;

public record RuntimeMaintenanceResponse(
        boolean executed,
        long payloadsPurged,
        long rateWindowsDeleted,
        long remainingPayloadBacklog,
        String completedAt) {
}
