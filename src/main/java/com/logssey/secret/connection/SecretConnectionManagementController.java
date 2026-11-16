package com.logssey.secret.connection;

import com.logssey.secret.connection.SecretConnectionManagementContracts.*;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/secrets/connections")
public class SecretConnectionManagementController {
    private final SecretConnectionManagementService service;

    public SecretConnectionManagementController(SecretConnectionManagementService service) {
        this.service = service;
    }

    @GetMapping("/setup-options")
    public Map<String, Object> options(Authentication auth) {
        return service.options(login(auth));
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> create(
            @RequestBody Create request, Authentication auth) {
        return ResponseEntity.status(201).body(service.create(login(auth), request));
    }

    @GetMapping("/{id}/settings")
    public Map<String, Object> settings(@PathVariable long id, Authentication auth) {
        return service.settings(login(auth), id);
    }

    @PatchMapping("/{id}/settings")
    public Map<String, Object> change(
            @PathVariable long id, @RequestBody SettingsChange request, Authentication auth) {
        return service.change(login(auth), id, request);
    }

    @PutMapping("/{id}/targets")
    public Map<String, Object> targets(
            @PathVariable long id, @RequestBody TargetsChange request, Authentication auth) {
        return service.targets(login(auth), id, request);
    }

    @DeleteMapping("/{id}/credential")
    public Map<String, Object> disable(
            @PathVariable long id, @RequestParam long expectedScopeVersion, Authentication auth) {
        return service.disableCredential(login(auth), id, expectedScopeVersion);
    }

    @GetMapping("/{id}/github/repositories")
    public Map<String, Object> repositories(
            @PathVariable long id,
            @RequestParam(defaultValue = "1") int page,
            Authentication auth) {
        return service.repositories(login(auth), id, page);
    }

    @PostMapping("/{id}/credential/restore")
    public Map<String, Object> restore(
            @PathVariable long id, @RequestBody SettingsChange request, Authentication auth) {
        if (request == null || request.expectedScopeVersion() == null)
            throw new com.logssey.common.error.ApiException(
                    com.logssey.common.error.ErrorCode.INVALID_INPUT);
        return service.restoreCredential(login(auth), id, request.expectedScopeVersion());
    }

    @GetMapping("/{id}/github/branches")
    public Map<String, Object> branches(
            @PathVariable long id,
            @RequestParam String repository,
            @RequestParam(defaultValue = "1") int page,
            Authentication auth) {
        return service.branches(login(auth), id, repository, page);
    }

    private static String login(Authentication auth) {
        return auth == null ? null : auth.getName();
    }
}
