package com.logssey.secret.response;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/secrets")
public class SecretExplanationController {
    private final SecretExplanationService service;

    public SecretExplanationController(SecretExplanationService service) { this.service = service; }

    @GetMapping("/runs/{id}/explanation")
    public SecretExplanationResponse runReadiness(@PathVariable long id, Authentication authentication) {
        return service.run(id, login(authentication), false);
    }

    @PostMapping("/runs/{id}/explanation")
    public SecretExplanationResponse explainRun(@PathVariable long id, Authentication authentication) {
        return service.run(id, login(authentication), true);
    }

    @GetMapping("/cases/{id}/explanation")
    public SecretExplanationResponse caseReadiness(@PathVariable long id, Authentication authentication) {
        return service.responseCase(id, login(authentication), false);
    }

    @PostMapping("/cases/{id}/explanation")
    public SecretExplanationResponse explainCase(@PathVariable long id, Authentication authentication) {
        return service.responseCase(id, login(authentication), true);
    }

    private static String login(Authentication authentication) {
        return authentication == null ? null : authentication.getName();
    }
}
