package com.logssey.secret.validation;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/secrets")
public class SecretValidationController {
    private final SecretValidationService service;

    public SecretValidationController(SecretValidationService service) {
        this.service = service;
    }

    private String login(Authentication a) {
        return a == null ? null : a.getName();
    }

    @GetMapping("/{id}/validation")
    public Map<String, Object> read(
            @PathVariable long id,
            @RequestParam(required = false) Long occurrenceId,
            Authentication a) {
        return service.read(id, occurrenceId, login(a));
    }

    @PostMapping("/{id}/validation-requests")
    public ResponseEntity<Map<String, Object>> request(
            @PathVariable long id, @RequestBody Map<String, Object> body, Authentication a) {
        return ResponseEntity.accepted().body(service.request(id, body, login(a)));
    }

    @GetMapping("/validation-requests/{id}")
    public Map<String, Object> requestStatus(@PathVariable long id, Authentication a) {
        return service.requestStatus(id, login(a));
    }

    @GetMapping("/{id}/validation-history")
    public Map<String, Object> history(
            @PathVariable long id,
            @RequestParam(required = false) Long occurrenceId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            Authentication a) {
        return service.history(id, occurrenceId, page, size, login(a));
    }

    @GetMapping("/scopes/{id}/validation-policy")
    public Map<String, Object> policy(@PathVariable long id, Authentication a) {
        return service.policy(id, login(a));
    }

    @PatchMapping("/scopes/{id}/validation-policy")
    public Map<String, Object> policy(
            @PathVariable long id, @RequestBody Map<String, Object> body, Authentication a) {
        return service.updatePolicy(id, body, login(a));
    }
}
