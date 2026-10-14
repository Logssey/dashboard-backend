package com.logssey.runtime.ingest.dto;

import tools.jackson.databind.JsonNode;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public record FalcoEventEnvelope(
        @NotBlank String clusterId,
        Long sensorId,
        @NotBlank String schemaVersion,
        @NotNull JsonNode event) {
}
