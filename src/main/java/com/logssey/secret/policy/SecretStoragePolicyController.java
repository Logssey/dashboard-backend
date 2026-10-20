package com.logssey.secret.policy;

import com.logssey.secret.policy.SecretPolicyContracts.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/secrets")
public class SecretStoragePolicyController {
    private final SecretStoragePolicyService service;
    public SecretStoragePolicyController(SecretStoragePolicyService service) { this.service=service; }

    @GetMapping("/scopes")
    public Page<Classification> scopes(@RequestParam(defaultValue="NEEDS_REVIEW") String classificationStatus,
                                      @RequestParam(defaultValue="0") int page,@RequestParam(defaultValue="20") int size,
                                      Authentication authentication) {
        return service.scopes(classificationStatus,page,size,login(authentication));
    }
    @GetMapping("/scopes/{scopeId}/classification")
    public Classification classification(@PathVariable long scopeId,Authentication authentication) {
        return service.classification(scopeId,login(authentication));
    }
    @PostMapping("/scopes/{scopeId}/classification-proposals")
    @ResponseStatus(HttpStatus.CREATED)
    public Classification propose(@PathVariable long scopeId,@RequestBody ProposalRequest request,Authentication authentication) {
        return service.propose(scopeId,request,login(authentication));
    }
    @PostMapping("/scopes/{scopeId}/classification-proposals/{proposalId}/approve")
    public Classification approveProposal(@PathVariable long scopeId,@PathVariable long proposalId,
                                          @RequestBody ApproveProposalRequest request,Authentication authentication) {
        return service.approveProposal(scopeId,proposalId,request,login(authentication));
    }
    @PostMapping("/scopes/{scopeId}/classification-proposals/{proposalId}/reject")
    public Classification rejectProposal(@PathVariable long scopeId,@PathVariable long proposalId,
                                         @RequestBody RejectProposalRequest request,Authentication authentication) {
        return service.rejectProposal(scopeId,proposalId,request,login(authentication));
    }
    @GetMapping("/storage-policies")
    public Page<PolicySummary> policies(@RequestParam(defaultValue="ACTIVE") String status,
                                       @RequestParam(defaultValue="0") int page,@RequestParam(defaultValue="20") int size,
                                       Authentication authentication) {
        return service.policies(status,page,size,login(authentication));
    }
    @GetMapping("/storage-policies/{policyId}/versions/{version}")
    public PolicySummary policy(@PathVariable long policyId,@PathVariable long version,Authentication authentication) {
        return service.policy(policyId,version,login(authentication));
    }
    @PostMapping("/storage-policies/drafts")
    @ResponseStatus(HttpStatus.CREATED)
    public PolicySummary draft(@RequestBody DraftRequest request,Authentication authentication) {
        return service.draft(request,login(authentication));
    }
    @PostMapping("/storage-policies/{policyId}/versions/{version}/approve")
    public PolicySummary approvePolicy(@PathVariable long policyId,@PathVariable long version,
                                       @RequestBody VersionRequest request,Authentication authentication) {
        return service.approvePolicy(policyId,version,request,login(authentication));
    }
    @PostMapping("/storage-policies/{policyId}/retire")
    public PolicySummary retire(@PathVariable long policyId,@RequestBody RetireRequest request,Authentication authentication) {
        return service.retire(policyId,request,login(authentication));
    }
    private static String login(Authentication authentication) { return authentication==null?null:authentication.getName(); }
}
