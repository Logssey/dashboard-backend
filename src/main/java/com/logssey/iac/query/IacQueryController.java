package com.logssey.iac.query;

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
