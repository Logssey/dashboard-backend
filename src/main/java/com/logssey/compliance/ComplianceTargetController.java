package com.logssey.compliance;

import java.security.Principal;

import static com.logssey.compliance.ComplianceTargetDtos.ConnectionTestResponse;
import static com.logssey.compliance.ComplianceTargetDtos.CreateTargetRequest;
import static com.logssey.compliance.ComplianceTargetDtos.TargetListResponse;
import static com.logssey.compliance.ComplianceTargetDtos.TargetSummary;
import static com.logssey.compliance.ComplianceTargetDtos.UpdateTargetRequest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/compliance/targets")
public class ComplianceTargetController {

    private final ComplianceTargetService service;

    public ComplianceTargetController(ComplianceTargetService service) {
        this.service = service;
    }

    @GetMapping
    public TargetListResponse list() {
        return service.list();
    }

    @GetMapping("/{targetKey}")
    public TargetSummary target(@PathVariable String targetKey) {
        return service.target(targetKey);
    }

    @PostMapping
    public TargetSummary create(Principal principal, @RequestBody CreateTargetRequest request) {
        return service.create(principal == null ? null : principal.getName(), request);
    }

    @PatchMapping("/{targetKey}")
    public TargetSummary update(Principal principal, @PathVariable String targetKey,
                                @RequestBody UpdateTargetRequest request) {
        return service.update(principal == null ? null : principal.getName(), targetKey, request);
    }

    @PostMapping("/{targetKey}/connection-tests")
    public ConnectionTestResponse verify(Principal principal, @PathVariable String targetKey) {
        return service.verify(principal == null ? null : principal.getName(), targetKey);
    }
}
