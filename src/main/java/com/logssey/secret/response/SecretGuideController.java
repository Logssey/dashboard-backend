package com.logssey.secret.response;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/secrets/cases")
public class SecretGuideController {
    private final SecretGuideService service;

    SecretGuideController(SecretGuideService service) {
        this.service = service;
    }

    /** No request body: prompts are built entirely from server-owned enum fields. */
    @PostMapping("/{caseId}/guide")
    public SecretGuideResponse guide(@PathVariable long caseId, Authentication authentication) {
        return service.guide(caseId, authentication == null ? null : authentication.getName());
    }
}
