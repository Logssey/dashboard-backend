package com.logssey.iac.query;

import com.logssey.iac.auth.IacCiSecurityConfig;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/iac")
public class IacQueryController {

    private final IacQueryService service;

    public IacQueryController(IacQueryService service) {
        this.service = service;
    }

    @GetMapping("/summary")
    public IacSummaryResponse summary(Authentication authentication) {
        return service.summary(name(authentication));
    }

    @GetMapping("/paths")
    public IacPathListResponse paths(@RequestParam(defaultValue = "OPEN") String status,
                                     @RequestParam(required = false) Integer tier,
                                     @RequestParam(required = false) Long cursor,
                                     @RequestParam(defaultValue = "20") int limit,
                                     Authentication authentication) {
        return service.paths(status, tier, cursor, limit, name(authentication));
    }

    @GetMapping("/prs")
    public java.util.List<IacPullRequestSummaryResponse> pullRequests(@RequestParam(required = false) String repo,
                                                                      Authentication authentication) {
        return service.pullRequests(repo, name(authentication));
    }

    /** run 하나의 결과. infrastructure 의 iac-report(GitHub OIDC)는 자기 레포의 run 만 본다 */
    @GetMapping("/runs/{runId}/result")
    public IacPullRequestResponse runResult(@PathVariable long runId, Authentication authentication) {
        var ci = IacCiSecurityConfig.ciCaller(authentication);
        return ci.isPresent() ? service.runResultByCi(runId, ci.get()) : service.runResult(runId, name(authentication));
    }

    @GetMapping("/paths/{pathId}")
    public IacPathDetailResponse path(@PathVariable long pathId, Authentication authentication) {
        return service.path(pathId, name(authentication));
    }

    @GetMapping("/remediations/suggested")
    public java.util.List<IacRemediationResponse> remediations(Authentication authentication) {
        return service.remediations(name(authentication));
    }

    @GetMapping("/gates")
    public IacGatesResponse gates(@RequestParam(required = false) String repo, Authentication authentication) {
        return service.gates(repo, name(authentication));
    }

    @GetMapping("/jobs")
    public java.util.List<IacJobStatusResponse> jobs(Authentication authentication) {
        return service.jobs(name(authentication));
    }

    @GetMapping("/drifts")
    public java.util.List<IacDriftResponse> drifts(@RequestParam(defaultValue = "OPEN") String status,
                                                   Authentication authentication) {
        return service.drifts(status, name(authentication));
    }

    @GetMapping("/state/summary")
    public IacStateSummaryResponse stateSummary(Authentication authentication) {
        return service.stateSummary(name(authentication));
    }

    @GetMapping("/prs/{number}")
    public IacPullRequestResponse pullRequest(@PathVariable int number, @RequestParam(required = false) String repo,
                                              Authentication authentication) {
        return service.pullRequest(number, repo, name(authentication));
    }

    private static String name(Authentication authentication) {
        return authentication == null ? null : authentication.getName();
    }
}
