package com.logssey.secret.risk;

import java.security.Principal;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/secrets/occurrences/{id}/severity-overrides")
public class SecretSeverityOverrideController {
  final SecretSeverityOverrideService service;

  public SecretSeverityOverrideController(SecretSeverityOverrideService service) {
    this.service = service;
  }

  @PostMapping
  public ResponseEntity<Map<String, Object>> propose(
      @PathVariable long id,
      @RequestBody SecretSeverityOverrideService.Proposal r,
      Principal actor) {
    return ResponseEntity.status(201).body(service.propose(actor.getName(), id, r));
  }

  @PostMapping("/{assessmentId}/decisions")
  public Map<String, Object> decide(
      @PathVariable long id,
      @PathVariable long assessmentId,
      @RequestBody SecretSeverityOverrideService.Decision r,
      Principal actor) {
    return service.decide(actor.getName(), id, assessmentId, r);
  }
}
