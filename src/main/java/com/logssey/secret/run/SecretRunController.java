package com.logssey.secret.run;

import java.net.URI;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/secrets/runs")
public class SecretRunController {

    private final SecretRunService service;

    public SecretRunController(SecretRunService service) {
        this.service = service;
    }

    @PostMapping
    public ResponseEntity<SecretRunAcceptedResponse> register(@Valid @RequestBody SecretRunRequest request,
                                                               Authentication authentication) {
        var accepted = service.register(request, authentication == null ? null : authentication.getName());
        return ResponseEntity.accepted()
                .location(URI.create("/api/v1/secrets/runs/" + accepted.runId()))
                .body(accepted);
    }

    @GetMapping("/{runId}")
    public SecretRunStatusResponse status(@PathVariable long runId, Authentication authentication) {
        return service.status(runId, authentication == null ? null : authentication.getName());
    }

    @GetMapping
    public SecretRunListResponse list(@RequestParam(defaultValue = "0") int page,
                                      @RequestParam(defaultValue = "20") int size,
                                      Authentication authentication) {
        return service.list(page, size, authentication == null ? null : authentication.getName());
    }
}
