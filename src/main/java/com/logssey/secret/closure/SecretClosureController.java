package com.logssey.secret.closure;

import java.security.Principal;
import java.util.Map;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import static com.logssey.secret.closure.SecretClosureContracts.*;

@RestController
@RequestMapping("/api/v1/secrets/cases/{caseId}")
public class SecretClosureController {
    private final SecretClosureService closure;
    private final SecretGovernanceService governance;
    public SecretClosureController(SecretClosureService closure,SecretGovernanceService governance) {this.closure=closure;this.governance=governance;}
    @GetMapping("/closure-checks")
    public ClosureChecks checks(@PathVariable long caseId,Principal principal) {return closure.checks(principal.getName(),caseId);}
    @PostMapping("/resolution-decisions")
    public Mutation resolve(@PathVariable long caseId,@RequestBody ResolutionRequest request,Principal principal) {return closure.resolve(principal.getName(),caseId,request);}
    @PostMapping("/dismissal-decisions")
    public Mutation dismiss(@PathVariable long caseId,@RequestBody DismissalRequest request,Principal principal) {return closure.dismiss(principal.getName(),caseId,request);}
    @GetMapping("/exceptions")
    public Exceptions exceptions(@PathVariable long caseId,Principal principal) {return governance.exceptions(principal.getName(),caseId);}
    @PostMapping("/exceptions")
    public Mutation exception(@PathVariable long caseId,@RequestBody ExceptionRequest request,Principal principal) {return governance.approveException(principal.getName(),caseId,request);}
    @PostMapping("/exceptions/revoke")
    public Mutation revoke(@PathVariable long caseId,@RequestBody RevokeRequest request,Principal principal) {return governance.revoke(principal.getName(),caseId,request);}
    @GetMapping("/transfer-evidence")
    public TransferList transfers(@PathVariable long caseId,Principal principal) {return governance.transfers(principal.getName(),caseId);}
    @PostMapping("/transfer-evidence")
    public Mutation transfer(@PathVariable long caseId,@RequestBody TransferRequest request,Principal principal) {return governance.transfer(principal.getName(),caseId,request);}
    @PostMapping("/transfer-evidence/{evidenceId}/reviews")
    public Mutation review(@PathVariable long caseId,@PathVariable long evidenceId,@RequestBody TransferReview request,Principal principal) {
        return governance.reviewTransfer(principal.getName(),caseId,evidenceId,request);
    }
}

@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice(assignableTypes=SecretClosureController.class)
class SecretClosureErrors {
    @ExceptionHandler(SecretClosureConflict.class)
    ResponseEntity<Map<String,Object>> conflict(SecretClosureConflict error) {
        return ResponseEntity.status(409).body(Map.of("code","CONFLICT","message",error.getMessage(),
            "details",Map.of("reasonCode","CLOSURE_BLOCKED","closureChecks",error.checks())));
    }
}
