package com.logssey.runtime.query;

import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;

import com.logssey.runtime.query.dto.RuntimeSensorListResponse.SensorItem;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class RuntimeSensorHealthEvaluator {

    private final Duration degradedAfter;
    private final Duration offlineAfter;

    public RuntimeSensorHealthEvaluator(
            @Value("${logssey.runtime.sensor-degraded-after:PT2M}") Duration degradedAfter,
            @Value("${logssey.runtime.sensor-offline-after:PT5M}") Duration offlineAfter) {
        if (degradedAfter.isNegative() || degradedAfter.isZero()
                || offlineAfter.compareTo(degradedAfter) <= 0) {
            throw new IllegalArgumentException(
                    "Runtime sensor offline threshold must be greater than the degraded threshold.");
        }
        this.degradedAfter = degradedAfter;
        this.offlineAfter = offlineAfter;
    }

    public List<SensorItem> evaluate(List<SensorItem> sensors, Instant now) {
        return sensors.stream().map(sensor -> evaluate(sensor, now)).toList();
    }

    SensorItem evaluate(SensorItem sensor, Instant now) {
        Instant heartbeat = parse(sensor.lastHeartbeatAt());
        String effectiveStatus;
        if (heartbeat == null) {
            effectiveStatus = parse(sensor.lastEventAt()) == null ? "UNKNOWN" : "DEGRADED";
        } else {
            Duration age = Duration.between(heartbeat, now);
            if (age.compareTo(offlineAfter) > 0) {
                effectiveStatus = "OFFLINE";
            } else if (age.compareTo(degradedAfter) > 0) {
                effectiveStatus = "DEGRADED";
            } else {
                effectiveStatus = sensor.status();
            }
        }
        if (effectiveStatus.equals(sensor.status())) {
            return sensor;
        }
        return new SensorItem(
                sensor.sensorId(), sensor.clusterId(), sensor.nodeName(), sensor.type(), sensor.version(),
                sensor.driver(), effectiveStatus, sensor.lastHeartbeatAt(), sensor.lastEventAt(),
                sensor.ruleSetVersion(), sensor.queueDepth(), sensor.error());
    }

    private static Instant parse(String value) {
        if (value == null) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException ignored) {
            return null;
        }
    }
}
