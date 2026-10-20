package com.logssey.secret.response;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/secrets/cases/{caseId}")
public class SecretRevalidationController {
    private final SecretRevalidationService service;

    SecretRevalidationController(SecretRevalidationService service) {
        this.service = service;
    }

    @PostMapping("/revalidations")
    @ResponseStatus(HttpStatus.ACCEPTED)
    public SecretRevalidationResult request(@PathVariable long caseId,
                                            @RequestBody SecretRevalidationRequest request,
                                            Authentication authentication) {
        return service.request(caseId, request, loginId(authentication));
    }

    @GetMapping("/revalidations")
    public List<SecretRevalidationResult> list(@PathVariable long caseId,
                                               Authentication authentication) {
        return service.list(caseId, loginId(authentication));
    }

    @PostMapping("/resolve")
    public SecretCaseDetail resolve(@PathVariable long caseId,
                                    @RequestBody SecretResolveRequest request,
                                    Authentication authentication) {
        return service.resolve(caseId, request, loginId(authentication));
    }

    @PostMapping("/revalidation-resume")
    public java.util.Map<String,Object> resume(@PathVariable long caseId,
                                   @RequestBody SecretResumeRequest request,
                                   Authentication authentication) {
        return service.resume(caseId, request, loginId(authentication));
    }

    private static String loginId(Authentication authentication) {
        return authentication == null ? null : authentication.getName();
    }
}
