package com.logssey.runtime.ingest;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Optional;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class RuntimeIngestRepository {

    private final JdbcClient jdbcClient;

    public RuntimeIngestRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public RawEventInsert insertRawEvent(String clusterId, Long sensorId, String sourceEventId,
                                         String idempotencyKey, String schemaVersion, String payload,
                                         String payloadSha256, String maskedFields,
                                         Instant receivedAt, Instant payloadRetentionUntil) {
        Optional<Long> inserted = jdbcClient.sql("""
                        INSERT INTO runtime_raw_events
                            (cluster_id, sensor_type, sensor_id, source_event_id, idempotency_key,
                             schema_version, payload, payload_sha256, masked_fields, processing_status,
                             received_at, payload_retention_until)
                        VALUES
                            (:clusterId, 'FALCO', :sensorId, :sourceEventId, :idempotencyKey,
                             :schemaVersion, CAST(:payload AS jsonb), :payloadSha256,
                             CAST(:maskedFields AS jsonb), 'RECEIVED', :receivedAt, :payloadRetentionUntil)
                        ON CONFLICT (cluster_id, sensor_type, idempotency_key) DO NOTHING
                        RETURNING raw_event_id
                        """)
                .param("clusterId", clusterId)
                .param("sensorId", sensorId)
                .param("sourceEventId", sourceEventId)
                .param("idempotencyKey", idempotencyKey)
                .param("schemaVersion", schemaVersion)
                .param("payload", payload)
                .param("payloadSha256", payloadSha256)
                .param("maskedFields", maskedFields)
                .param("receivedAt", utc(receivedAt))
                .param("payloadRetentionUntil", utc(payloadRetentionUntil))
                .query(Long.class)
                .optional();
        if (inserted.isPresent()) {
            return new RawEventInsert(inserted.get(), false);
        }
        long existing = jdbcClient.sql("""
                        SELECT raw_event_id
                        FROM runtime_raw_events
                        WHERE cluster_id = :clusterId AND sensor_type = 'FALCO' AND idempotency_key = :idempotencyKey
                        """)
                .param("clusterId", clusterId)
                .param("idempotencyKey", idempotencyKey)
                .query(Long.class)
                .single();
        return new RawEventInsert(existing, true);
    }

    public ExistingOutcome findOutcome(long rawEventId) {
        return jdbcClient.sql("""
                        SELECT r.processing_status, e.runtime_event_id, fe.finding_id
                        FROM runtime_raw_events r
                        LEFT JOIN runtime_events e ON e.raw_event_id = r.raw_event_id
                        LEFT JOIN runtime_finding_events fe ON fe.runtime_event_id = e.runtime_event_id
                        WHERE r.raw_event_id = :rawEventId
                        """)
                .param("rawEventId", rawEventId)
                .query((rs, rowNum) -> new ExistingOutcome(
                        rs.getString("processing_status"),
                        nullableLong(rs, "runtime_event_id"),
                        nullableLong(rs, "finding_id")))
                .single();
    }

    public long ensureCommonWorkloadAsset(String workloadName) {
        return jdbcClient.sql("""
                        INSERT INTO assets (name, provider, asset_type, environment)
                        VALUES (:name, 'KUBERNETES', 'Deployment', 'PROD')
                        ON CONFLICT (provider, name, environment)
                        DO UPDATE SET name = EXCLUDED.name
                        RETURNING asset_id
                        """)
                .param("name", workloadName)
                .query(Long.class)
                .single();
    }

    public long upsertRuntimeAsset(Long commonAssetId, NormalizedRuntimeEvent.AssetSnapshot asset, Instant observedAt) {
        return jdbcClient.sql("""
                        INSERT INTO runtime_assets
                            (asset_id, cluster_id, namespace, workload_kind, workload_name, pod_uid, pod_name,
                             container_id, container_name, image, image_digest, node_name, service_account_name,
                             valid_from, snapshot_at)
                        VALUES
                            (:assetId, :clusterId, :namespace, :workloadKind, :workloadName, :podUid, :podName,
                             :containerId, :containerName, :image, :imageDigest, :nodeName, :serviceAccountName,
                             :observedAt, :observedAt)
                        ON CONFLICT (cluster_id, namespace, pod_name, container_id)
                        DO UPDATE SET
                            asset_id = COALESCE(EXCLUDED.asset_id, runtime_assets.asset_id),
                            workload_kind = COALESCE(EXCLUDED.workload_kind, runtime_assets.workload_kind),
                            workload_name = COALESCE(EXCLUDED.workload_name, runtime_assets.workload_name),
                            pod_uid = COALESCE(EXCLUDED.pod_uid, runtime_assets.pod_uid),
                            container_name = COALESCE(EXCLUDED.container_name, runtime_assets.container_name),
                            image = COALESCE(EXCLUDED.image, runtime_assets.image),
                            image_digest = COALESCE(EXCLUDED.image_digest, runtime_assets.image_digest),
                            node_name = COALESCE(EXCLUDED.node_name, runtime_assets.node_name),
                            service_account_name = COALESCE(EXCLUDED.service_account_name, runtime_assets.service_account_name),
                            snapshot_at = EXCLUDED.snapshot_at,
                            updated_at = CURRENT_TIMESTAMP
                        RETURNING runtime_asset_id
                        """)
                .param("assetId", commonAssetId)
                .param("clusterId", asset.clusterId())
                .param("namespace", asset.namespace())
                .param("workloadKind", asset.workloadKind())
                .param("workloadName", asset.workloadName())
                .param("podUid", asset.podUid())
                .param("podName", asset.podName())
                .param("containerId", asset.containerId())
                .param("containerName", asset.containerName())
                .param("image", asset.image())
                .param("imageDigest", asset.imageDigest())
                .param("nodeName", asset.nodeName())
                .param("serviceAccountName", asset.serviceAccountName())
                .param("observedAt", utc(observedAt))
                .query(Long.class)
                .single();
    }

    public Optional<Long> findMatchingSuppression(NormalizedRuntimeEvent event) {
        return jdbcClient.sql("""
                        SELECT suppression_id
                        FROM runtime_suppressions
                        WHERE rule_key = :ruleKey
                          AND cluster_id = :clusterId
                          AND created_at <= :occurredAt
                          AND expires_at > :occurredAt
                          AND (revoked_at IS NULL OR revoked_at > :occurredAt)
                          AND (namespace IS NULL OR namespace = :namespace)
                          AND (workload_name IS NULL OR workload_name = :workloadName)
                          AND (process_executable IS NULL OR process_executable = :processExecutable)
                          AND (target_name_prefix IS NULL
                               OR left(:targetName, length(target_name_prefix)) = target_name_prefix)
                          AND (operation IS NULL OR operation = :operation)
                        ORDER BY
                          ((namespace IS NOT NULL)::int + (workload_name IS NOT NULL)::int
                           + (process_executable IS NOT NULL)::int + (target_name_prefix IS NOT NULL)::int
                           + (operation IS NOT NULL)::int) DESC,
                          created_at DESC,
                          suppression_id DESC
                        LIMIT 1
                        """)
                .param("ruleKey", event.ruleKey())
                .param("clusterId", event.asset().clusterId())
                .param("occurredAt", utc(event.occurredAt()))
                .param("namespace", event.asset().namespace())
                .param("workloadName", event.asset().workloadName())
                .param("processExecutable", event.process().executable())
                .param("targetName", event.target().name())
                .param("operation", event.target().operation())
                .query(Long.class)
                .optional();
    }

    public boolean acquireRateLimitSlot(NormalizedRuntimeEvent event, Instant receivedAt, int limit) {
        return jdbcClient.sql("""
                        INSERT INTO runtime_ingest_rate_windows
                            (cluster_id, node_name, rule_key, window_started_at,
                             received_count, processed_count, rate_limited_count)
                        VALUES
                            (:clusterId, :nodeName, :ruleKey, :windowStartedAt, 1, 1, 0)
                        ON CONFLICT (cluster_id, node_name, rule_key, window_started_at)
                        DO UPDATE SET
                            received_count = runtime_ingest_rate_windows.received_count + 1,
                            processed_count = runtime_ingest_rate_windows.processed_count
                                + CASE WHEN runtime_ingest_rate_windows.received_count < :eventLimit THEN 1 ELSE 0 END,
                            rate_limited_count = runtime_ingest_rate_windows.rate_limited_count
                                + CASE WHEN runtime_ingest_rate_windows.received_count >= :eventLimit THEN 1 ELSE 0 END,
                            updated_at = CURRENT_TIMESTAMP
                        RETURNING received_count <= :eventLimit
                        """)
                .param("clusterId", event.asset().clusterId())
                .param("nodeName", event.asset().nodeName() == null ? "unknown" : event.asset().nodeName())
                .param("ruleKey", event.ruleKey())
                .param("windowStartedAt", utc(receivedAt.truncatedTo(java.time.temporal.ChronoUnit.MINUTES)))
                .param("eventLimit", limit)
                .query(Boolean.class)
                .single();
    }

    public long insertRuntimeEvent(long rawEventId, Long runtimeAssetId, Long suppressionId,
                                   NormalizedRuntimeEvent event, String arguments,
                                   String missingFields, Instant receivedAt) {
        return jdbcClient.sql("""
                        INSERT INTO runtime_events
                            (raw_event_id, runtime_asset_id, source, source_event_id, event_type, rule_key,
                             rule_version, rule_mode, source_priority, occurred_at, received_at, process_id,
                             parent_process_id, process_executable, process_arguments, parent_executable,
                             user_id, target_type, target_name, operation,
                             normalization_status, missing_fields, asset_resolution_status,
                             handling_status, suppression_id)
                        VALUES
                            (:rawEventId, :runtimeAssetId, 'FALCO', :sourceEventId, :eventType, :ruleKey,
                             :ruleVersion, :ruleMode, :sourcePriority, :occurredAt, :receivedAt, :processId,
                             :parentProcessId, :processExecutable, CAST(:arguments AS jsonb), :parentExecutable,
                             :userId, :targetType, :targetName, :operation,
                             :normalizationStatus, CAST(:missingFields AS jsonb), :assetResolutionStatus,
                             :handlingStatus, :suppressionId)
                        RETURNING runtime_event_id
                        """)
                .param("rawEventId", rawEventId)
                .param("runtimeAssetId", runtimeAssetId)
                .param("sourceEventId", event.sourceEventId())
                .param("eventType", event.eventType())
                .param("ruleKey", event.ruleKey())
                .param("ruleVersion", event.ruleVersion())
                .param("ruleMode", event.ruleMode().name())
                .param("sourcePriority", event.sourcePriority())
                .param("occurredAt", utc(event.occurredAt()))
                .param("receivedAt", utc(receivedAt))
                .param("processId", event.process().processId())
                .param("parentProcessId", event.process().parentProcessId())
                .param("processExecutable", event.process().executable())
                .param("arguments", arguments)
                .param("parentExecutable", event.process().parentExecutable())
                .param("userId", event.process().userId())
                .param("targetType", event.target().type())
                .param("targetName", event.target().name())
                .param("operation", event.target().operation())
                .param("normalizationStatus", event.normalizationStatus())
                .param("missingFields", missingFields)
                .param("assetResolutionStatus", runtimeAssetId == null ? "UNRESOLVED" : "RESOLVED")
                .param("handlingStatus", suppressionId != null ? "SUPPRESSED"
                        : event.ruleMode() == RuntimeRuleDefinition.Mode.OBSERVE ? "OBSERVED" : "GROUPED")
                .param("suppressionId", suppressionId)
                .query(Long.class)
                .single();
    }

    public long upsertFinding(String fingerprint, Long runtimeAssetId, Long commonAssetId,
                              NormalizedRuntimeEvent event) {
        return jdbcClient.sql("""
                        INSERT INTO runtime_findings
                            (fingerprint, rule_key, rule_title, rule_version, runtime_asset_id, asset_id,
                             source_priority, evaluation_status, first_seen_at, last_seen_at,
                             process_executable, parent_executable, user_id,
                             target_type, target_name, operation)
                        VALUES
                            (:fingerprint, :ruleKey, :ruleTitle, :ruleVersion, :runtimeAssetId, :assetId,
                             :sourcePriority, 'PENDING_CONTEXT', :occurredAt, :occurredAt,
                             :processExecutable, :parentExecutable, :userId,
                             :targetType, :targetName, :operation)
                        ON CONFLICT (fingerprint)
                        DO UPDATE SET
                            first_seen_at = LEAST(runtime_findings.first_seen_at, EXCLUDED.first_seen_at),
                            last_seen_at = GREATEST(runtime_findings.last_seen_at, EXCLUDED.last_seen_at),
                            occurrence_count = runtime_findings.occurrence_count + 1,
                            updated_at = CURRENT_TIMESTAMP
                        RETURNING finding_id
                        """)
                .param("fingerprint", fingerprint)
                .param("ruleKey", event.ruleKey())
                .param("ruleTitle", event.ruleTitle())
                .param("ruleVersion", event.ruleVersion())
                .param("runtimeAssetId", runtimeAssetId)
                .param("assetId", commonAssetId)
                .param("sourcePriority", event.sourcePriority())
                .param("occurredAt", utc(event.occurredAt()))
                .param("processExecutable", event.process().executable())
                .param("parentExecutable", event.process().parentExecutable())
                .param("userId", event.process().userId())
                .param("targetType", event.target().type())
                .param("targetName", event.target().name())
                .param("operation", event.target().operation())
                .query(Long.class)
                .single();
    }

    public void linkFindingEvent(long findingId, long runtimeEventId) {
        jdbcClient.sql("""
                        INSERT INTO runtime_finding_events (finding_id, runtime_event_id)
                        VALUES (:findingId, :runtimeEventId)
                        ON CONFLICT (runtime_event_id) DO NOTHING
                        """)
                .param("findingId", findingId)
                .param("runtimeEventId", runtimeEventId)
                .update();
    }

    public void updateRawStatus(long rawEventId, String status, String errorCode) {
        jdbcClient.sql("""
                        UPDATE runtime_raw_events
                        SET processing_status = :status, error_code = :errorCode
                        WHERE raw_event_id = :rawEventId
                        """)
                .param("status", status)
                .param("errorCode", errorCode)
                .param("rawEventId", rawEventId)
                .update();
    }

    /**
     * Falcosidekick does not know the dashboard's numeric sensor id. The first event from a node
     * therefore creates the natural (cluster, node, type) sensor identity and later heartbeats
     * enrich the same row with version and driver information.
     */
    public long upsertFalcoSensorFromEvent(String clusterId, String nodeName, Instant eventAt) {
        return jdbcClient.sql("""
                        INSERT INTO runtime_sensors
                            (cluster_id, node_name, sensor_type, status, last_event_at)
                        VALUES (:clusterId, :nodeName, 'FALCO', 'HEALTHY', :eventAt)
                        ON CONFLICT (cluster_id, node_name, sensor_type)
                        DO UPDATE SET
                            status = CASE
                                WHEN runtime_sensors.status = 'OFFLINE' THEN 'HEALTHY'
                                ELSE runtime_sensors.status
                            END,
                            last_event_at = GREATEST(runtime_sensors.last_event_at, EXCLUDED.last_event_at),
                            updated_at = CURRENT_TIMESTAMP
                        RETURNING sensor_id
                        """)
                .param("clusterId", clusterId)
                .param("nodeName", nodeName)
                .param("eventAt", utc(eventAt))
                .query(Long.class)
                .single();
    }

    public void attachSensor(long rawEventId, long sensorId) {
        jdbcClient.sql("""
                        UPDATE runtime_raw_events
                        SET sensor_id = :sensorId
                        WHERE raw_event_id = :rawEventId AND sensor_id IS NULL
                        """)
                .param("sensorId", sensorId)
                .param("rawEventId", rawEventId)
                .update();
    }

    public void touchSensor(Long sensorId, Instant eventAt) {
        if (sensorId == null) {
            return;
        }
        jdbcClient.sql("""
                        UPDATE runtime_sensors
                        SET last_event_at = :eventAt, updated_at = CURRENT_TIMESTAMP
                        WHERE sensor_id = :sensorId
                        """)
                .param("eventAt", utc(eventAt))
                .param("sensorId", sensorId)
                .update();
    }

    private static OffsetDateTime utc(Instant instant) {
        return OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
    }

    private static Long nullableLong(java.sql.ResultSet rs, String column) throws java.sql.SQLException {
        long value = rs.getLong(column);
        return rs.wasNull() ? null : value;
    }

    public record RawEventInsert(long rawEventId, boolean duplicate) {
    }

    public record ExistingOutcome(String processingStatus, Long runtimeEventId, Long findingId) {
    }
}
