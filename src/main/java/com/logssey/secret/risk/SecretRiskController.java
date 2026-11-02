package com.logssey.secret.risk;

import java.security.Principal;
import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/secrets")
public class SecretRiskController {
  final SecretRiskQueryService query;
  final SecretAssessmentRequests requests;

  public SecretRiskController(SecretRiskQueryService query, SecretAssessmentRequests requests) {
    this.query = query;
    this.requests = requests;
  }

  @GetMapping("/occurrences/{id}/risk")
  public Map<String, Object> risk(@PathVariable long id, Principal actor) {
    return query.risk(actor.getName(), id);
  }

  @GetMapping("/occurrences/{id}/risk-assets")
  public Map<String, Object> assets(
      @PathVariable long id,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "20") int size,
      Principal actor) {
    return query.assets(actor.getName(), id, page, size);
  }

  @GetMapping("/occurrences/{id}/assessment-history")
  public Map<String, Object> history(
      @PathVariable long id,
      @RequestParam(defaultValue = "0") int page,
      @RequestParam(defaultValue = "20") int size,
      Principal actor) {
    return query.history(actor.getName(), id, page, size);
  }

  @PostMapping("/occurrences/{id}/assessment-requests")
  public ResponseEntity<Map<String, Object>> request(
      @PathVariable long id,
      @RequestBody SecretAssessmentRequests.Request request,
      Principal actor) {
    return ResponseEntity.accepted().body(requests.request(actor.getName(), id, request));
  }

  @GetMapping("/assessment-requests/{id}")
  public Map<String, Object> status(@PathVariable long id, Principal actor) {
    return requests.status(actor.getName(), id);
  }
}
