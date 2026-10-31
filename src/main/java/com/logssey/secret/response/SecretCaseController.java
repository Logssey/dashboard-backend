package com.logssey.secret.response;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@RestController
@RequestMapping("/api/v1/secrets")
public class SecretCaseController {
    private final SecretCaseService service;
    private final SecretLocationWorkflow workflow;
    private final com.logssey.secret.query.SecretWorkbenchService workbench;

    public SecretCaseController(SecretCaseService service, SecretLocationWorkflow workflow,com.logssey.secret.query.SecretWorkbenchService workbench) {
        this.service = service;
        this.workflow = workflow;
        this.workbench=workbench;
    }

    @GetMapping("/cases")
    public java.util.Map<String,Object> list(@RequestParam(defaultValue = "0") int page,
                                       @RequestParam(defaultValue = "20") int size,
                                       @RequestParam(defaultValue = "PRODUCTION") String origin,
                                       @RequestParam(defaultValue = "currentCases") String scope,
                                       @RequestParam(required = false) String stages,
                                       @RequestParam(required = false) String assignmentStatus,
                                       @RequestParam(required = false) String assignee,
                                       @RequestParam(defaultValue="ALL") String source,@RequestParam(defaultValue="ALL") String provider,
                                       @RequestParam(defaultValue="ALL") String environment,@RequestParam(required=false) Long connectionId,
                                       @RequestParam(required=false) String snapshotId,
                                       @RequestParam(defaultValue="ALL") String severity,@RequestParam(defaultValue="ALL") String validity,
                                       Authentication authentication) {
        if(scope.equals("currentCases")&&assignmentStatus==null)return workbench.queue(loginId(authentication),
            new com.logssey.secret.query.SecretWorkbenchService.Filters(origin,source,provider,environment,connectionId,assignee),"CURRENT_CASES",stages,page,size,snapshotId,severity,validity);
        if(snapshotId!=null||!source.equals("ALL")||!provider.equals("ALL")||!environment.equals("ALL")||connectionId!=null||!severity.equals("ALL")||!validity.equals("ALL"))
            throw new com.logssey.common.error.ApiException(com.logssey.common.error.ErrorCode.INVALID_INPUT);
        return workflow.list(loginId(authentication),origin,scope,stages,assignmentStatus,assignee,page,size);
    }

    @PostMapping("/{secretId}/cases")
    @ResponseStatus(HttpStatus.CREATED)
    public SecretCaseDetail open(@PathVariable long secretId,
                                 @RequestBody SecretCaseOpenRequest request,
                                 Authentication authentication) {
        throw new com.logssey.common.error.ApiException(com.logssey.common.error.ErrorCode.CONFLICT,
                "발견 위치의 노출 판정과 조치 요청을 함께 등록해 주세요.");
    }

    @GetMapping("/cases/{caseId}")
    public java.util.Map<String,Object> detail(@PathVariable long caseId, Authentication authentication) {
        return workflow.detail(caseId, loginId(authentication));
    }

    @GetMapping("/assignees")
    public java.util.Map<String,Object> assignees(@RequestParam long caseId,
                                                 @RequestParam(required=false) Long occurrenceId,
                                                 Authentication authentication) {
        return workflow.assignees(caseId, occurrenceId, loginId(authentication));
    }

    @PatchMapping("/cases/{caseId}/assignment")
    public java.util.Map<String,Object> assign(@PathVariable long caseId,
                                   @RequestBody SecretLocationWorkflow.Coordinator request,
                                   Authentication authentication) {
        return workflow.coordinator(caseId, request, loginId(authentication));
    }

    @PostMapping("/cases/{caseId}/review")
    public SecretCaseDetail review(@PathVariable long caseId,
                                   @RequestBody SecretCaseReviewRequest request,
                                   Authentication authentication) {
        workflow.rejectLegacy(caseId, loginId(authentication));
        throw new IllegalStateException();
    }

    @PostMapping("/cases/{caseId}/start")
    public SecretCaseDetail start(@PathVariable long caseId,
                                  @RequestBody SecretCaseStartRequest request,
                                  Authentication authentication) {
        workflow.rejectLegacy(caseId, loginId(authentication));
        throw new IllegalStateException();
    }

    @PatchMapping("/cases/{caseId}/checklist/{itemId}")
    public java.util.Map<String,Object> checklist(@PathVariable long caseId, @PathVariable long itemId,
                                      @RequestBody SecretLocationWorkflow.Checklist request,
                                      Authentication authentication) {
        return workflow.checklist(caseId, itemId, request, loginId(authentication));
    }

    @PostMapping("/cases/{caseId}/actions")
    public com.logssey.secret.command.SecretCommandResult action(@PathVariable long caseId,
                                   @RequestBody SecretLocationWorkflow.Action request,
                                   Authentication authentication) {
        return workflow.action(caseId, request, loginId(authentication));
    }

    @PatchMapping("/cases/{caseId}/occurrences/{occurrenceId}/assignment")
    public java.util.Map<String,Object> assignLocation(@PathVariable long caseId,@PathVariable long occurrenceId,
            @RequestBody SecretLocationWorkflow.Assignment request,Authentication authentication) {
        return workflow.assign(caseId,occurrenceId,request,loginId(authentication));
    }

    @PostMapping("/cases/{caseId}/occurrences/{occurrenceId}/complete-actions")
    public com.logssey.secret.command.SecretCommandResult complete(@PathVariable long caseId,@PathVariable long occurrenceId,
            @RequestBody SecretLocationWorkflow.Completion request,Authentication authentication) {
        return workflow.complete(caseId,occurrenceId,request,loginId(authentication));
    }

    @GetMapping("/cases/{caseId}/activities")
    public java.util.Map<String,Object> activities(@PathVariable long caseId,@RequestParam(defaultValue="0") int page,
            @RequestParam(defaultValue="20") int size,Authentication authentication) {
        return workflow.activities(caseId,loginId(authentication),page,size);
    }

    private static String loginId(Authentication authentication) {
        return authentication == null ? null : authentication.getName();
    }
}
