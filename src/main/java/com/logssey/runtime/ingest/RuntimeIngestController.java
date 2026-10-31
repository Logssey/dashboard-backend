package com.logssey.runtime.ingest;

import com.logssey.runtime.ingest.dto.FalcoEventEnvelope;
import com.logssey.runtime.ingest.dto.RuntimeIngestResponse;
import tools.jackson.databind.JsonNode;

import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/v1/runtime/events")
public class RuntimeIngestController {

    private final RuntimeIngestService ingestService;

    public RuntimeIngestController(RuntimeIngestService ingestService) {
        this.ingestService = ingestService;
    }

    @PostMapping("/falco")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public RuntimeIngestResponse falco(
            @Valid @RequestBody FalcoEventEnvelope envelope,
            @RequestHeader(name = "Idempotency-Key", required = false) String idempotencyKey) {
        return ingestService.ingestFalco(envelope, idempotencyKey);
    }

    /** Falcosidekick webhook adapter. Cluster metadata is supplied by its fixed output headers. */
    @PostMapping("/falco/raw")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public RuntimeIngestResponse falcoRaw(
            @RequestHeader("X-Runtime-Cluster-Id") String clusterId,
            @RequestHeader(name = "X-Runtime-Schema-Version", defaultValue = "falco-json-0.1") String schemaVersion,
            @RequestHeader(name = "Idempotency-Key", required = false) String idempotencyKey,
            @RequestBody JsonNode event) {
        return ingestService.ingestFalco(
                new FalcoEventEnvelope(clusterId, null, schemaVersion, event), idempotencyKey);
    }
}
