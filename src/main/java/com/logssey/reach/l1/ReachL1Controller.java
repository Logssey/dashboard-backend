package com.logssey.reach.l1;

import java.security.Principal;
import java.util.List;

import com.logssey.reach.l1.dto.ReachInventoryResponse;
import com.logssey.reach.l1.dto.ReachWorkloadPageResponse;

import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/reach")
public class ReachL1Controller {
    private final ReachL1Service service;

    public ReachL1Controller(ReachL1Service service) {
        this.service = service;
    }

    /** API-07. 쉼표로 준 값은 Spring이 목록으로 나눈다 (app=API,WEB) */
    @GetMapping("/workloads")
    public ReachWorkloadPageResponse workloads(
            Principal principal,
            @RequestParam(required = false) List<String> namespace,
            @RequestParam(required = false) List<String> app,
            @RequestParam(required = false) String digest,
            @RequestParam(required = false) List<String> deployment,
            @RequestParam(required = false) Integer size,
            @RequestParam(required = false) String cursor,
            @RequestParam(required = false) String include) {
        var filter = new ReachWorkloadFilter(namespace, app, digest, deployment);
        return service.workloads(principal == null ? null : principal.getName(), filter, size, cursor, include);
    }

    /**
     * L1 업로드. ADMIN 세션(수동) 또는 클러스터 수집기의 서비스 계정 토큰.
     * 토큰은 ReachTokenSecurityConfig가 수집기 서비스 계정만 이 경로에 들인다
     */
    @PutMapping("/l1/workloads")
    public ReachInventoryResponse upload(Principal principal, @RequestBody ReachInventoryRequest request) {
        if (principal instanceof JwtAuthenticationToken token) {
            return service.uploadFromCollector(token.getToken().getSubject(), request);
        }
        return service.upload(principal == null ? null : principal.getName(), request);
    }
}
