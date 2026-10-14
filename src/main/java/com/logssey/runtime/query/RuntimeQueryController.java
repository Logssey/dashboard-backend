package com.logssey.runtime.query;

import java.security.Principal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import com.logssey.runtime.query.dto.RuntimeFindingListResponse;
import com.logssey.runtime.query.dto.RuntimeFindingResponse;
import com.logssey.runtime.query.dto.RuntimeFindingUpdateRequest;
import com.logssey.runtime.query.dto.RuntimeOverviewResponse;
import com.logssey.runtime.query.dto.RuntimeSensorListResponse;

import jakarta.validation.Valid;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/runtime")
public class RuntimeQueryController {

    private final RuntimeQueryService service;

    public RuntimeQueryController(RuntimeQueryService service) {
        this.service = service;
    }

    @GetMapping("/overview")
    public RuntimeOverviewResponse overview(
            @RequestParam(defaultValue = "logssey-prod") String clusterId,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to) {
        Instant rangeTo = to == null ? Instant.now() : to;
        Instant rangeFrom = from == null ? rangeTo.minus(24, ChronoUnit.HOURS) : from;
        return service.overview(clusterId, rangeFrom, rangeTo);
    }

    @GetMapping("/findings")
    public RuntimeFindingListResponse findings(
            @RequestParam(defaultValue = "logssey-prod") String clusterId,
            @RequestParam(defaultValue = "ALL") String namespace,
            @RequestParam(defaultValue = "ALL") String reviewStatus,
            @RequestParam(defaultValue = "ALL") String ruleKey,
            @RequestParam(defaultValue = "50") int limit) {
        return service.findings(clusterId, namespace, reviewStatus, ruleKey, limit);
    }

    @GetMapping("/findings/{findingId}")
    public RuntimeFindingResponse finding(@PathVariable long findingId) {
        return service.finding(findingId);
    }

    @PatchMapping("/findings/{findingId}")
    public RuntimeFindingResponse updateFinding(@PathVariable long findingId,
                                                Principal principal,
                                                @Valid @RequestBody RuntimeFindingUpdateRequest request) {
        return service.updateFinding(findingId, principal.getName(), request);
    }

    @GetMapping("/sensors")
    public RuntimeSensorListResponse sensors(
            @RequestParam(defaultValue = "logssey-prod") String clusterId) {
        return service.sensors(clusterId);
    }
}
