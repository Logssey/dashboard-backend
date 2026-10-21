package com.logssey.secret.risk;
import java.security.Principal;
import java.util.Map;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/api/v1/secrets/occurrences/{id}/risk-evidence")
public class SecretRiskEvidenceController {
 private final SecretRiskEvidenceService service;
 public SecretRiskEvidenceController(SecretRiskEvidenceService service){this.service=service;}
 @PostMapping public ResponseEntity<Map<String,Object>> submit(@PathVariable long id,@RequestBody SecretRiskEvidenceService.Submission request,Principal actor){return ResponseEntity.status(201).body(service.submit(actor.getName(),id,request));}
 @PostMapping("/{evidenceId}/decisions") public Map<String,Object> decide(@PathVariable long id,@PathVariable long evidenceId,@RequestBody SecretRiskEvidenceService.Decision request,Principal actor){return service.decide(actor.getName(),id,evidenceId,request);}
}
