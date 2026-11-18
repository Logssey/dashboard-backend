package com.logssey.iac.job;

import java.net.URI;

import com.logssey.iac.auth.IacCollectorSecurityConfig;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/iac/jobs")
public class IacJobController {

    private final IacJobService service;

    public IacJobController(IacJobService service) {
        this.service = service;
    }

    @PostMapping("/{job}/trigger")
    public ResponseEntity<JobTriggeredResponse> trigger(@org.springframework.web.bind.annotation.PathVariable String job,
                                                        Authentication authentication) {
        return ResponseEntity.accepted().body(service.trigger(job, authentication == null ? null : authentication.getName()));
    }

    @PostMapping("/collect-graph/runs")
    public ResponseEntity<CollectGraphRunResponse> recordCollectGraph(@Valid @RequestBody CollectGraphRunRequest request,
                                                                      Authentication authentication) {
        // 대시보드 호스트의 수집기(IacCollectorSecurityConfig)는 사람이 아니므로 SYSTEM 으로 기록한다
        boolean collector = authentication != null && authentication.getAuthorities().stream()
                .anyMatch(a -> IacCollectorSecurityConfig.AUTHORITY.equals(a.getAuthority()));
        var recorded = collector ? service.recordCollectGraphBySystem(request)
                : service.recordCollectGraph(request, authentication == null ? null : authentication.getName());
        return ResponseEntity.created(URI.create("/api/v1/iac/jobs/" + recorded.jobId())).body(recorded);
    }
}
