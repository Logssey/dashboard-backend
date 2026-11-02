package com.logssey.overview;

import com.logssey.overview.dto.response.AssetSummaryResponse;
import com.logssey.overview.dto.response.OverviewSummaryResponse;
import com.logssey.overview.dto.response.PriorityFindingListResponse;
import com.logssey.overview.dto.response.RiskTrendResponse;

import java.security.Principal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** 통합 현황 API (API 명세 OVERVIEW). 모두 로그인 필요 */
@RestController
@RequestMapping("/api/v1/overview")
public class OverviewController {

    private final OverviewService overviewService;

    public OverviewController(OverviewService overviewService) {
        this.overviewService = overviewService;
    }

    @GetMapping("/summary")
    public OverviewSummaryResponse summary(Principal principal, @RequestParam(defaultValue = "ALL") String environment) {
        return overviewService.getSummary(EnvironmentFilter.from(environment), principal.getName());
    }

    @GetMapping("/risk-trend")
    public RiskTrendResponse riskTrend(Principal principal, @RequestParam(defaultValue = "ALL") String environment,
                                       @RequestParam(defaultValue = "7") int days) {
        return overviewService.getRiskTrend(EnvironmentFilter.from(environment), days, principal.getName());
    }

    @GetMapping("/assets")
    public AssetSummaryResponse assets(@RequestParam(defaultValue = "ALL") String environment) {
        return overviewService.getAssetSummary(EnvironmentFilter.from(environment));
    }

    @GetMapping("/priority-findings")
    public PriorityFindingListResponse priorityFindings(Principal principal, @RequestParam(defaultValue = "ALL") String environment,
                                                        @RequestParam(defaultValue = "4") int limit) {
        return overviewService.getPriorityFindings(EnvironmentFilter.from(environment), limit, principal.getName());
    }
}
