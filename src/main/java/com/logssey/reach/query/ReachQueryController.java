package com.logssey.reach.query;

import java.security.Principal;
import java.util.List;

import com.logssey.reach.query.dto.ReachFindingDetailResponse;
import com.logssey.reach.query.dto.ReachFindingPageResponse;
import com.logssey.reach.query.dto.ReachSummaryResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/reach")
public class ReachQueryController {
    private final ReachQueryService service;

    public ReachQueryController(ReachQueryService service) {
        this.service = service;
    }

    /** API-04. 쉼표로 준 값은 Spring이 목록으로 나눈다 (status=REACHABLE,UNKNOWN) */
    @GetMapping("/findings")
    public ReachFindingPageResponse findings(
            Principal principal,
            @RequestParam(required = false) List<String> status,
            @RequestParam(required = false) List<String> severity,
            @RequestParam(required = false) List<String> reviewState,
            @RequestParam(required = false) List<String> deployment,
            @RequestParam(required = false) String cveContains,
            @RequestParam(required = false) Integer size,
            @RequestParam(required = false) String cursor,
            @RequestParam(required = false) String include)
             {
        var filter = new ReachFindingFilter(status, severity, reviewState, deployment, cveContains);
        return service.findings(principal == null ? null : principal.getName(), filter, size, cursor, include);
    }

    /** API-08 */
    @GetMapping("/summary") 
    public ReachSummaryResponse summary(Principal principal,
                                        @RequestParam(required = false) List<String> deployment,
                                        @RequestParam(required = false) List<String> include) {
        return service.summary(principal == null ? null : principal.getName(), deployment, include);
    }

    /** API-05 */
    @GetMapping("/findings/{findingId}")
    public ReachFindingDetailResponse finding(Principal principal, @PathVariable long findingId) {
        return service.finding(principal == null ? null : principal.getName(), findingId);
    }
}

