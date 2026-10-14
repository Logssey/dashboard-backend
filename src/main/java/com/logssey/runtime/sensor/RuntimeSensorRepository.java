package com.logssey.runtime.sensor;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import com.logssey.runtime.sensor.dto.RuntimeSensorHeartbeatRequest;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

@Repository
public class RuntimeSensorRepository {

    private final JdbcClient jdbcClient;

    public RuntimeSensorRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    public long upsertHeartbeat(RuntimeSensorHeartbeatRequest request, Instant receivedAt) {
        return jdbcClient.sql("""
                        INSERT INTO runtime_sensors
                            (cluster_id, node_name, sensor_type, version, driver, rule_set_version,
                             status, last_heartbeat_at, queue_depth, error_message)
                        VALUES
                            (:clusterId, :nodeName, :sensorType, :version, :driver, :ruleSetVersion,
                             :status, :receivedAt, :queueDepth, :error)
                        ON CONFLICT (cluster_id, node_name, sensor_type)
                        DO UPDATE SET
                            version = COALESCE(EXCLUDED.version, runtime_sensors.version),
                            driver = COALESCE(EXCLUDED.driver, runtime_sensors.driver),
                            rule_set_version = COALESCE(EXCLUDED.rule_set_version, runtime_sensors.rule_set_version),
                            status = EXCLUDED.status,
                            last_heartbeat_at = EXCLUDED.last_heartbeat_at,
                            queue_depth = EXCLUDED.queue_depth,
                            error_message = EXCLUDED.error_message,
                            updated_at = CURRENT_TIMESTAMP
                        RETURNING sensor_id
                        """)
                .param("clusterId", request.clusterId().trim())
                .param("nodeName", request.nodeName().trim())
                .param("sensorType", request.sensorType())
                .param("version", trimToNull(request.version()))
                .param("driver", trimToNull(request.driver()))
                .param("ruleSetVersion", trimToNull(request.ruleSetVersion()))
                .param("status", request.status())
                .param("receivedAt", OffsetDateTime.ofInstant(receivedAt, ZoneOffset.UTC))
                .param("queueDepth", request.queueDepth())
                .param("error", trimToNull(request.error()))
                .query(Long.class)
                .single();
    }

    private static String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }
}
