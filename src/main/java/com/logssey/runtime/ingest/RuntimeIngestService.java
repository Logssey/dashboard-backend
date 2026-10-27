package com.logssey.runtime.ingest;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

import tools.jackson.core.JacksonException;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.runtime.ingest.RuntimeIngestRepository.ExistingOutcome;
import com.logssey.runtime.ingest.RuntimeIngestRepository.RawEventInsert;
import com.logssey.runtime.ingest.RuntimePayloadMasker.MaskedPayload;
import com.logssey.runtime.ingest.dto.FalcoEventEnvelope;
import com.logssey.runtime.ingest.dto.RuntimeIngestResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class RuntimeIngestService {

    private static final long FINDING_BUCKET_SECONDS = 300;

    private final RuntimePayloadMasker payloadMasker;
    private final FalcoRuntimeEventNormalizer normalizer;
    private final RuntimeIngestRepository repository;
    private final ObjectMapper objectMapper;
    private final TransactionTemplate transactionTemplate;
    private final int maxPayloadBytes;
    private final int maxEventsPerRuleNodeMinute;
    private final Duration rawPayloadRetention;

    public RuntimeIngestService(RuntimePayloadMasker payloadMasker,
                                FalcoRuntimeEventNormalizer normalizer,
                                RuntimeIngestRepository repository,
                                ObjectMapper objectMapper,
                                TransactionTemplate transactionTemplate,
                                @Value("${logssey.runtime.max-payload-bytes:262144}") int maxPayloadBytes,
                                @Value("${logssey.runtime.max-events-per-rule-node-minute:300}")
                                int maxEventsPerRuleNodeMinute,
                                @Value("${logssey.runtime.raw-payload-retention:P30D}") Duration rawPayloadRetention) {
        this.payloadMasker = payloadMasker;
        this.normalizer = normalizer;
        this.repository = repository;
        this.objectMapper = objectMapper;
        this.transactionTemplate = transactionTemplate;
        this.maxPayloadBytes = Math.max(1024, maxPayloadBytes);
        this.maxEventsPerRuleNodeMinute = Math.max(1, maxEventsPerRuleNodeMinute);
        this.rawPayloadRetention = rawPayloadRetention.isNegative() || rawPayloadRetention.isZero()
                ? Duration.ofDays(30) : rawPayloadRetention;
    }

    public RuntimeIngestResponse ingestFalco(FalcoEventEnvelope envelope, String requestedIdempotencyKey) {
        if (envelope.clusterId() == null || envelope.clusterId().isBlank()
                || envelope.schemaVersion() == null || envelope.schemaVersion().isBlank()
                || envelope.event() == null || envelope.event().isNull()) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "clusterId, schemaVersion, event는 필수입니다.");
        }
        Instant receivedAt = Instant.now();
        if (json(envelope.event()).getBytes(StandardCharsets.UTF_8).length > maxPayloadBytes) {
            throw new ApiException(ErrorCode.PAYLOAD_TOO_LARGE, "런타임 이벤트 본문이 허용 크기를 초과했습니다.");
        }
        MaskedPayload masked = payloadMasker.mask(envelope.event());
        String payload = json(masked.payload());
        String sourceEventId = sourceEventId(masked.payload(), payload);
        String idempotencyKey = normalizeIdempotencyKey(requestedIdempotencyKey, sourceEventId, payload);

        RawEventInsert raw = repository.insertRawEvent(
                envelope.clusterId(), envelope.sensorId(), sourceEventId, idempotencyKey,
                envelope.schemaVersion(), payload, RuntimeHashing.sha256(payload),
                json(masked.maskedFields()), receivedAt, receivedAt.plus(rawPayloadRetention));
        if (raw.duplicate()) {
            ExistingOutcome existing = repository.findOutcome(raw.rawEventId());
            return response(raw.rawEventId(), existing.runtimeEventId(), existing.findingId(), true,
                    existing.processingStatus(), receivedAt);
        }

        try {
            return transactionTemplate.execute(status -> process(envelope, masked, raw.rawEventId(), receivedAt));
        } catch (RuntimeException e) {
            repository.updateRawStatus(raw.rawEventId(), "FAILED", "RUNTIME_NORMALIZATION_FAILED");
            throw e;
        }
    }

    private RuntimeIngestResponse process(FalcoEventEnvelope envelope, MaskedPayload masked,
                                          long rawEventId, Instant receivedAt) {
            RuntimeNormalizationResult normalization = normalizer.normalize(
                    envelope.clusterId(), masked.payload(), receivedAt);
            if (normalization.normalizedEvent().isEmpty()) {
                repository.updateRawStatus(rawEventId, "IGNORED", normalization.ignoredReason());
                return response(rawEventId, null, null, false, "IGNORED", receivedAt);
            }

            NormalizedRuntimeEvent event = normalization.normalizedEvent().orElseThrow();
            Long sensorId = envelope.sensorId();
            if (sensorId == null && event.asset().nodeName() != null) {
                sensorId = repository.upsertFalcoSensorFromEvent(
                        envelope.clusterId(), event.asset().nodeName(), event.occurredAt());
                repository.attachSensor(rawEventId, sensorId);
            }
            if (!repository.acquireRateLimitSlot(event, receivedAt, maxEventsPerRuleNodeMinute)) {
                repository.updateRawStatus(rawEventId, "RATE_LIMITED", null);
                repository.touchSensor(sensorId, event.occurredAt());
                return response(rawEventId, null, null, false, "RATE_LIMITED", receivedAt);
            }
            Long commonAssetId = null;
            Long runtimeAssetId = null;
            if (event.asset().resolvable()) {
                if (event.asset().workloadName() != null) {
                    commonAssetId = repository.ensureCommonWorkloadAsset(event.asset().workloadName());
                }
                runtimeAssetId = repository.upsertRuntimeAsset(commonAssetId, event.asset(), event.occurredAt());
            }

            Long suppressionId = repository.findMatchingSuppression(event).orElse(null);
            long runtimeEventId = repository.insertRuntimeEvent(
                    rawEventId, runtimeAssetId, suppressionId, event,
                    json(event.process().arguments()), json(event.missingFields()), receivedAt);
            if (suppressionId != null) {
                repository.updateRawStatus(rawEventId, "SUPPRESSED", null);
                repository.touchSensor(sensorId, event.occurredAt());
                return response(rawEventId, runtimeEventId, null, false, "SUPPRESSED", receivedAt);
            }
            String fingerprint = fingerprint(event);
            long findingId = repository.upsertFinding(fingerprint, runtimeAssetId, commonAssetId, event);
            repository.linkFindingEvent(findingId, runtimeEventId);
            repository.updateRawStatus(rawEventId, "GROUPED", null);
            repository.touchSensor(sensorId, event.occurredAt());
            return response(rawEventId, runtimeEventId, findingId, false, "GROUPED", receivedAt);
    }

    private String sourceEventId(JsonNode payload, String serialized) {
        for (String field : new String[] {"uuid", "event_id", "id"}) {
            if (payload.hasNonNull(field) && !payload.path(field).asText().isBlank()) {
                return trim(payload.path(field).asText(), 160);
            }
        }
        return RuntimeHashing.sha256(serialized);
    }

    private static String normalizeIdempotencyKey(String requested, String sourceEventId, String payload) {
        String value = requested == null || requested.isBlank()
                ? "falco-" + sourceEventId
                : requested.trim();
        return value.length() <= 200 ? value : "sha256-" + RuntimeHashing.sha256(value + payload);
    }

    private static String fingerprint(NormalizedRuntimeEvent event) {
        long bucket = event.occurredAt().getEpochSecond() / FINDING_BUCKET_SECONDS;
        NormalizedRuntimeEvent.AssetSnapshot asset = event.asset();
        NormalizedRuntimeEvent.ProcessSnapshot process = event.process();
        return RuntimeHashing.sha256(String.join("|",
                event.ruleKey(),
                value(asset.clusterId()),
                value(asset.podUid()),
                value(asset.podName()),
                value(asset.containerId()),
                value(process.executable()),
                value(process.parentExecutable()),
                value(process.userId()),
                value(event.target().type()),
                value(event.target().name()),
                value(event.target().operation()),
                Long.toString(bucket)));
    }

    private static String value(Object value) {
        return Objects.toString(value, "");
    }

    private RuntimeIngestResponse response(long rawEventId, Long runtimeEventId, Long findingId,
                                           boolean duplicate, String status, Instant receivedAt) {
        return new RuntimeIngestResponse(rawEventId, runtimeEventId, findingId, true, duplicate,
                status, receivedAt.toString());
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JacksonException e) {
            throw new IllegalArgumentException("Runtime event JSON serialization failed", e);
        }
    }

    private static String trim(String value, int maxLength) {
        return value.length() <= maxLength ? value : value.substring(0, maxLength);
    }
}
