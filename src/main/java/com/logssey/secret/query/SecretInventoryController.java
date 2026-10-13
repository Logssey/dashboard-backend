package com.logssey.secret.query;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/secrets")
public class SecretInventoryController {
    private final SecretInventoryService service;

    public SecretInventoryController(SecretInventoryService service) {
        this.service = service;
    }

    @GetMapping
    public SecretListResponse list(@RequestParam(defaultValue = "0") int page,
                                   @RequestParam(defaultValue = "20") int size,
                                   @RequestParam(defaultValue = "ALL") String issuer,
                                   @RequestParam(defaultValue = "ALL") String componentState,
                                   Authentication authentication) {
        return service.list(page, size, issuer, componentState, loginId(authentication));
    }

    @GetMapping("/connections")
    public SecretConnectionListResponse connections(Authentication authentication) {
        return service.connections(loginId(authentication));
    }

    @GetMapping("/{id}")
    public SecretDetailResponse detail(@PathVariable long id, Authentication authentication) {
        return service.detail(id, loginId(authentication));
    }

    private static String loginId(Authentication authentication) {
        return authentication == null ? null : authentication.getName();
    }
}
