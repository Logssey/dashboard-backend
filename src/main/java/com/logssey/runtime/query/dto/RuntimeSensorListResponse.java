package com.logssey.runtime.query.dto;

import java.util.List;

public record RuntimeSensorListResponse(List<SensorItem> items, String collectionState) {

    public record SensorItem(
            long sensorId,
            String clusterId,
            String nodeName,
            String type,
            String version,
            String driver,
            String status,
            String lastHeartbeatAt,
            String lastEventAt,
            String ruleSetVersion,
            Long queueDepth,
            String error) {
    }
}
