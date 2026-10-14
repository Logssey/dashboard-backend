package com.logssey.runtime.sensor.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.PositiveOrZero;
import jakarta.validation.constraints.Size;

public record RuntimeSensorHeartbeatRequest(
        @NotBlank @Size(max = 80) String clusterId,
        @NotBlank @Size(max = 120) String nodeName,
        @NotBlank @Pattern(regexp = "FALCO|TETRAGON") String sensorType,
        @Size(max = 80) String version,
        @Size(max = 40) String driver,
        @Size(max = 80) String ruleSetVersion,
        @NotBlank @Pattern(regexp = "HEALTHY|DEGRADED|UNKNOWN") String status,
        @PositiveOrZero Long queueDepth,
        @Size(max = 500) String error) {
}
