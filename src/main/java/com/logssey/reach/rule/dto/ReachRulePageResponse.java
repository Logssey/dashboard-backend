package com.logssey.reach.rule.dto;

import java.util.List;

/** 규칙 페이지 (명세 2-4). version은 이 응답을 만든 규칙 데이터 버전. totalCount는 include=total일 때만 */
public record ReachRulePageResponse(
        List<ReachRuleResponse> items,
        String nextCursor,
        boolean hasNext,
        Long totalCount,
        String version) {
}
