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
    private final com.logssey.secret.query.SecretWorkbenchService workbench;
    @org.springframework.beans.factory.annotation.Autowired
    public SecretDecisionController(SecretDecisionService service,com.logssey.secret.query.SecretWorkbenchService workbench) { this.service=service;this.workbench=workbench; }
    SecretDecisionController(SecretDecisionService service){this(service,null);}
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
    public Object queue(Principal actor,@RequestParam(defaultValue="NEEDS_DECISION") String bucket,
        @RequestParam(defaultValue="PRODUCTION") String origin,@RequestParam(defaultValue="0") int page,
        @RequestParam(defaultValue="20") int size,@RequestParam(defaultValue="ALL") String source,
        @RequestParam(defaultValue="ALL") String provider,@RequestParam(defaultValue="ALL") String environment,
        @RequestParam(required=false) Long connectionId,@RequestParam(required=false) String assignee,
        @RequestParam(required=false) String snapshotId,@RequestParam(required=false) String stages,
        @RequestParam Map<String,String> params) {
        if(!java.util.Set.of("bucket","origin","page","size","source","provider","environment","connectionId","assignee","snapshotId","stages","classificationStatus","gapOnly").containsAll(params.keySet()))throw new com.logssey.common.error.ApiException(com.logssey.common.error.ErrorCode.INVALID_INPUT);
        return workbench==null?service.queue(actor.getName(),bucket,origin,page,size):
            workbench.queue(actor.getName(),new com.logssey.secret.query.SecretWorkbenchService.Filters(origin,source,provider,environment,connectionId,assignee),bucket,stages,page,size,snapshotId);
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
