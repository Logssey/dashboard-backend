package com.logssey.runtime.operations;

import java.security.Principal;

import com.logssey.runtime.operations.dto.RuntimeMaintenanceResponse;
import com.logssey.runtime.operations.dto.RuntimeOperationsHealthResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/runtime/operations")
public class RuntimeOperationsController {

    private final RuntimeOperationsService service;

    public RuntimeOperationsController(RuntimeOperationsService service) {
        this.service = service;
    }

    @GetMapping("/health")
    public RuntimeOperationsHealthResponse health(Principal principal) {
        return service.health(principal.getName());
    }

    @PostMapping("/maintenance")
    public RuntimeMaintenanceResponse maintenance(Principal principal) {
        return service.runManual(principal.getName());
    }
}
