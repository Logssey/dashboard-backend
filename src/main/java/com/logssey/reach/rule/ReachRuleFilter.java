package com.logssey.reach.rule;

import java.util.List;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

/**
 * 규칙 목록(API-09) 필터. cve는 여러 개(OR), packagePrefix는 purl 앞부분 일치, fact는 그 사실(F-…)을 판정 조건에 쓰는 규칙.
 * sort는 id·cve(둘 다 CVE 연도·번호 순, 기본 id). updatedAt은 데이터에 변경 시각이 없어 받지 않는다
 */
record ReachRuleFilter(List<String> cve, String packagePrefix, String fact, String sort) {

    static final List<String> SORTS = List.of("id", "cve");

    ReachRuleFilter {
        cve = cve == null ? List.of() : List.copyOf(cve);
        for (String id : cve) {
            if (!ReachVulnFunctionData.CVE.matcher(id).matches()) throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        packagePrefix = packagePrefix == null || packagePrefix.isBlank() ? null : packagePrefix.trim();
        fact = fact == null || fact.isBlank() ? null : fact.trim();
        sort = sort == null || sort.isBlank() ? "id" : sort;
        if (!SORTS.contains(sort)) throw new ApiException(ErrorCode.INVALID_INPUT);
    }

    int fingerprint() {
        return toString().hashCode();
    }
}
