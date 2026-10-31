package com.logssey.runtime.policy;

import java.security.Principal;
import java.util.List;

import com.logssey.runtime.policy.dto.RuntimeSuppressionCreateRequest;
import com.logssey.runtime.policy.dto.RuntimeSuppressionResponse;
import com.logssey.runtime.policy.dto.RuntimeSuppressionRevokeRequest;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/runtime/suppressions")
public class RuntimeSuppressionController {

    private final RuntimeSuppressionService service;

    public RuntimeSuppressionController(RuntimeSuppressionService service) {
        this.service = service;
    }

    @GetMapping
    public List<RuntimeSuppressionResponse> findAll(
            Principal principal,
            @RequestParam(defaultValue = "true") boolean activeOnly) {
        return service.findAll(principal.getName(), activeOnly);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public RuntimeSuppressionResponse create(Principal principal,
                                             @RequestBody RuntimeSuppressionCreateRequest request) {
        return service.create(principal.getName(), request);
    }

    @PostMapping("/{suppressionId}/revoke")
    public RuntimeSuppressionResponse revoke(Principal principal,
                                             @PathVariable long suppressionId,
                                             @RequestBody RuntimeSuppressionRevokeRequest request) {
        return service.revoke(principal.getName(), suppressionId, request);
    }
}
