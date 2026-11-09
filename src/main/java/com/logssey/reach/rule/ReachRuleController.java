package com.logssey.reach.rule;

import java.security.Principal;
import java.util.List;

import com.logssey.reach.rule.dto.ReachRulePageResponse;
import com.logssey.reach.rule.dto.ReachRuleResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** 판정 규칙(API-09) 조회. 데이터는 분석기의 데이터 파일(data/rules.json)이다 */
@RestController
@RequestMapping("/api/v1/reach")
public class ReachRuleController {
    private final ReachRuleService service;

    public ReachRuleController(ReachRuleService service) {
        this.service = service;
    }

    /** API-09 목록 */
    @GetMapping("/rules")
    public ReachRulePageResponse rules(
            Principal principal,
            @RequestParam(required = false) List<String> cve,
            @RequestParam(name = "package", required = false) String packagePrefix,
            @RequestParam(required = false) String fact,
            @RequestParam(required = false) String sort,
            @RequestParam(required = false) Integer size,
            @RequestParam(required = false) String cursor,
            @RequestParam(required = false) List<String> include) {
        var filter = new ReachRuleFilter(cve, packagePrefix, fact, sort);
        return service.rules(principal == null ? null : principal.getName(), filter, size, cursor, include);
    }

    /** API-09 하나 (RULE-CVE-2026-89407) */
    @GetMapping("/rules/{ruleId}")
    public ReachRuleResponse rule(Principal principal, @PathVariable String ruleId,
                                  @RequestParam(required = false) List<String> include) {
        return service.rule(principal == null ? null : principal.getName(), ruleId, include);
    }
}
