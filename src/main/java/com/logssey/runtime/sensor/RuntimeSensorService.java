package com.logssey.runtime.sensor;

import java.time.Instant;

import com.logssey.runtime.sensor.dto.RuntimeSensorHeartbeatRequest;
import com.logssey.runtime.sensor.dto.RuntimeSensorHeartbeatResponse;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RuntimeSensorService {

    private final RuntimeSensorRepository repository;

    public RuntimeSensorService(RuntimeSensorRepository repository) {
        this.repository = repository;
    }

    @Transactional
    public RuntimeSensorHeartbeatResponse heartbeat(RuntimeSensorHeartbeatRequest request) {
        Instant receivedAt = Instant.now();
        long sensorId = repository.upsertHeartbeat(request, receivedAt);
        return new RuntimeSensorHeartbeatResponse(sensorId, true, request.status(), receivedAt.toString());
    }
}
