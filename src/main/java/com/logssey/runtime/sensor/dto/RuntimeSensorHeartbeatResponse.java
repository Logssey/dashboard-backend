package com.logssey.runtime.sensor.dto;

public record RuntimeSensorHeartbeatResponse(
        long sensorId,
        boolean accepted,
        String status,
        String receivedAt) {
}
