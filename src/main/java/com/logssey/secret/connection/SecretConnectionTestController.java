package com.logssey.secret.connection;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/secrets/connections")
public class SecretConnectionTestController {
    private final SecretConnectionTestService service;

    public SecretConnectionTestController(SecretConnectionTestService service) {
        this.service = service;
    }

    @PostMapping("/{connectionId}/test")
    public SecretConnectionTestResponse test(@PathVariable long connectionId, Authentication authentication) {
        return service.test(connectionId, authentication == null ? null : authentication.getName());
    }
}
