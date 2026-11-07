package com.logssey.secret.usage;

import java.security.Principal;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/secrets")
public class SecretUsageController {
    private final SecretUsageService service;
    public SecretUsageController(SecretUsageService service){this.service=service;}
    @GetMapping("/{credentialId}/usage") public Map<String,Object> read(@PathVariable long credentialId,@RequestParam long occurrenceId,@RequestParam(defaultValue="1")int page,@RequestParam(defaultValue="20")int pageSize,Principal actor){return service.read(actor.getName(),credentialId,occurrenceId,page,pageSize);}
    @PostMapping("/{credentialId}/usage-requests") @ResponseStatus(HttpStatus.ACCEPTED)
    public Map<String,Object> request(@PathVariable long credentialId,@RequestBody Map<String,Object> body,Principal actor){return service.request(actor.getName(),credentialId,SecretUsageContracts.decode(body,SecretUsageContracts.Request.class));}
    @GetMapping("/usage-requests/{requestId}") public Map<String,Object> status(@PathVariable long requestId,Principal actor){return service.status(actor.getName(),requestId);}
    @PostMapping("/{credentialId}/usage-observations") @ResponseStatus(HttpStatus.CREATED)
    public Map<String,Object> manual(@PathVariable long credentialId,@RequestBody Map<String,Object> body,Principal actor){return service.submit(actor.getName(),credentialId,SecretUsageContracts.decode(body,SecretUsageContracts.Manual.class));}
    @PostMapping("/usage-observations/{observationId}/decisions") public Map<String,Object> decide(@PathVariable long observationId,@RequestBody Map<String,Object> body,Principal actor){return service.decide(actor.getName(),observationId,SecretUsageContracts.decode(body,SecretUsageContracts.Decision.class));}
}
