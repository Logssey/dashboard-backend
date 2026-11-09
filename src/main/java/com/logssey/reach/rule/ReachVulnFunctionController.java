package com.logssey.reach.rule;

import java.security.Principal;
import java.util.List;

import com.logssey.reach.rule.dto.ReachVulnFunctionPageResponse;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** 취약 함수(API-10) 조회. 데이터는 분석기의 데이터 파일(data/vuln-functions.json)이다 */
@RestController
@RequestMapping("/api/v1/reach")
public class ReachVulnFunctionController {
    private final ReachVulnFunctionService vulnFunctions;

    public ReachVulnFunctionController(ReachVulnFunctionService vulnFunctions) {
        this.vulnFunctions = vulnFunctions;
    }

    /** API-10. 쉼표로 준 값은 Spring이 목록으로 나눈다 (cve=CVE-2026-13506,CVE-2026-0636) */
    @GetMapping("/vuln-functions")
    public ReachVulnFunctionPageResponse vulnFunctions(
            Principal principal,
            @RequestParam(required = false) List<String> cve,
            @RequestParam(name = "package", required = false) String packagePrefix,
            @RequestParam(required = false) String sort,
            @RequestParam(required = false) Integer size,
            @RequestParam(required = false) String cursor,
            @RequestParam(required = false) List<String> include) {
        var filter = new ReachVulnFunctionFilter(cve, packagePrefix, sort);
        return vulnFunctions.vulnFunctions(principal == null ? null : principal.getName(), filter, size, cursor, include);
    }
}
