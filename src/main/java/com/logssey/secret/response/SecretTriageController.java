package com.logssey.secret.response;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/secrets")
public class SecretTriageController {
    private final SecretTriageService service;

    public SecretTriageController(SecretTriageService service) {
        this.service = service;
    }

    @GetMapping("/triage-candidates")
    public SecretTriageCandidateList candidates(@RequestParam(defaultValue = "0") int page,
                                                @RequestParam(defaultValue = "20") int size,
                                                Authentication authentication) {
        return service.candidates(page, size, loginId(authentication));
    }

    @GetMapping("/triage-candidates/{secretId}")
    public SecretTriageCandidateDetail candidate(@PathVariable long secretId,
                                                 Authentication authentication) {
        return service.candidate(secretId, loginId(authentication));
    }

    @GetMapping("/scopes/{scopeId}/response-origin")
    public SecretScopeOriginResponse scope(@PathVariable long scopeId, Authentication authentication) {
        return service.scope(scopeId, loginId(authentication));
    }

    @PatchMapping("/scopes/{scopeId}/response-origin")
    public SecretScopeOriginResponse classify(@PathVariable long scopeId,
                                              @RequestBody SecretScopeOriginRequest request,
                                              Authentication authentication) {
        return service.classify(scopeId, request, loginId(authentication));
    }

    @GetMapping("/occurrences/{occurrenceId}/triage")
    public SecretOccurrenceTriageResponse occurrence(@PathVariable long occurrenceId,
                                                      Authentication authentication) {
        return service.occurrence(occurrenceId, loginId(authentication));
    }

    @PostMapping("/occurrences/{occurrenceId}/assessments")
    public SecretOccurrenceTriageResponse assess(@PathVariable long occurrenceId,
                                                  @RequestBody SecretExposureAssessmentRequest request,
                                                  Authentication authentication) {
        return service.assess(occurrenceId, request, loginId(authentication));
    }

    private static String loginId(Authentication authentication) {
        return authentication == null ? null : authentication.getName();
    }
}
