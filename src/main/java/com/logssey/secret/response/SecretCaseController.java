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
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@RestController
@RequestMapping("/api/v1/secrets")
public class SecretCaseController {
    private final SecretCaseService service;

    public SecretCaseController(SecretCaseService service) {
        this.service = service;
    }

    @GetMapping("/cases")
    public SecretCaseListResponse list(@RequestParam(defaultValue = "0") int page,
                                       @RequestParam(defaultValue = "20") int size,
                                       @RequestParam(defaultValue = "PRODUCTION") String origin,
                                       Authentication authentication) {
        return service.list(page, size, origin, loginId(authentication));
    }

    @PostMapping("/{secretId}/cases")
    @ResponseStatus(HttpStatus.CREATED)
    public SecretCaseDetail open(@PathVariable long secretId,
                                 @RequestBody SecretCaseOpenRequest request,
                                 Authentication authentication) {
        return service.open(secretId, request, loginId(authentication));
    }

    @GetMapping("/cases/{caseId}")
    public SecretCaseDetail detail(@PathVariable long caseId, Authentication authentication) {
        return service.detail(caseId, loginId(authentication));
    }

    @GetMapping("/assignees")
    public SecretAssigneeListResponse assignees(@RequestParam long caseId,
                                                 Authentication authentication) {
        return service.assignees(caseId, loginId(authentication));
    }

    @PatchMapping("/cases/{caseId}/assignment")
    public SecretCaseDetail assign(@PathVariable long caseId,
                                   @RequestBody SecretAssignmentRequest request,
                                   Authentication authentication) {
        return service.assign(caseId, request, loginId(authentication));
    }

    private static String loginId(Authentication authentication) {
        return authentication == null ? null : authentication.getName();
    }
}
