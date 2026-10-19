package com.logssey.iac.job;

import java.net.URI;

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

    @PostMapping("/collect-graph/runs")
    public ResponseEntity<CollectGraphRunResponse> recordCollectGraph(@Valid @RequestBody CollectGraphRunRequest request,
                                                                      Authentication authentication) {
        var recorded = service.recordCollectGraph(request, authentication == null ? null : authentication.getName());
        return ResponseEntity.created(URI.create("/api/v1/iac/jobs/" + recorded.jobId())).body(recorded);
    }
}
