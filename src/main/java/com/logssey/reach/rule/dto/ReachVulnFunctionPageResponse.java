package com.logssey.reach.rule.dto;

import java.util.List;

/**
 * 취약 함수 페이지 (명세 2-4). version·generated는 이 응답을 만든 데이터 파일의 버전과 생성 날짜다.
 * 스캔이 쓴 데이터 버전(API-03 tools.vulnFunctionsVersion)과 다를 수 있어 같이 보인다. totalCount는 include=total일 때만
 */
public record ReachVulnFunctionPageResponse(
        List<ReachVulnFunctionResponse> items,
        String nextCursor,
        boolean hasNext,
        Long totalCount,
        String version,
        String generated) {
}
