package com.logssey.secret.decision;

import java.security.Principal;
import java.util.Map;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import static com.logssey.secret.decision.SecretDecisionContracts.*;

@RestController
@RequestMapping("/api/v1/secrets")
public class SecretDecisionController {
    private final SecretDecisionService service;
    public SecretDecisionController(SecretDecisionService service) { this.service=service; }
    @GetMapping("/occurrences/{id}/review-context")
    public ReviewContext context(@PathVariable long id,Principal actor) { return service.context(actor.getName(),id); }
    @PostMapping("/occurrences/{id}/decisions")
    public DecisionResult decide(@PathVariable long id,@RequestBody DecisionRequest request,Principal actor) {
        return service.decide(actor.getName(),id,request);
    }
    @PostMapping("/occurrences/{id}/case-links")
    public DecisionResult link(@PathVariable long id,@RequestBody LinkRequest request,Principal actor) {
        return service.link(actor.getName(),id,request);
    }
    @GetMapping("/review-queue")
    public QueuePage queue(Principal actor,@RequestParam(defaultValue="NEEDS_DECISION") String bucket,
        @RequestParam(defaultValue="PRODUCTION") String origin,@RequestParam(defaultValue="0") int page,
        @RequestParam(defaultValue="20") int size) {
        return service.queue(actor.getName(),bucket,origin,page,size);
    }
}

@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice(assignableTypes=SecretDecisionController.class)
class SecretDecisionErrors {
    @ExceptionHandler(SecretReviewConflict.class)
    ResponseEntity<Map<String,Object>> conflict(SecretReviewConflict error) {
        return ResponseEntity.status(409).body(Map.of("code","CONFLICT","message",error.getMessage(),
            "details",Map.of("reasonCode","STALE_REVIEW_CONTEXT","changedFields",error.changedFields())));
    }
}
