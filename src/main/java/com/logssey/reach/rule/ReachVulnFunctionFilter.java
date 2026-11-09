package com.logssey.reach.rule;

import java.util.List;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

/**
 * 취약 함수 목록(API-10) 필터. cve는 여러 개(OR), packagePrefix는 purl 앞부분 일치, sort는 cve·class·method 중 하나(기본 cve).
 * 형식이 틀리면 INVALID_INPUT(400)
 */
record ReachVulnFunctionFilter(List<String> cve, String packagePrefix, String sort) {

    static final List<String> SORTS = List.of("cve", "class", "method");

    ReachVulnFunctionFilter {
        cve = cve == null ? List.of() : List.copyOf(cve);
        for (String id : cve) {
            if (!ReachVulnFunctionData.CVE.matcher(id).matches()) throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        packagePrefix = packagePrefix == null || packagePrefix.isBlank() ? null : packagePrefix.trim();
        sort = sort == null || sort.isBlank() ? "cve" : sort;
        if (!SORTS.contains(sort)) throw new ApiException(ErrorCode.INVALID_INPUT);
    }

    /** 커서가 이 필터로 만들어졌는지 확인하는 값. 커서와 함께 필터를 바꾸면 400이다 (명세 2-4) */
    int fingerprint() {
        return toString().hashCode();
    }
}
