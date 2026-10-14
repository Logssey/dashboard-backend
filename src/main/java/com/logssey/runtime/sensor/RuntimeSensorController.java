package com.logssey.runtime.sensor;

import com.logssey.runtime.sensor.dto.RuntimeSensorHeartbeatRequest;
import com.logssey.runtime.sensor.dto.RuntimeSensorHeartbeatResponse;

import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/v1/runtime/sensors")
public class RuntimeSensorController {

    private final RuntimeSensorService service;

    public RuntimeSensorController(RuntimeSensorService service) {
        this.service = service;
    }

    @PostMapping("/heartbeat")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public RuntimeSensorHeartbeatResponse heartbeat(
            @Valid @RequestBody RuntimeSensorHeartbeatRequest request) {
        return service.heartbeat(request);
    }
}
