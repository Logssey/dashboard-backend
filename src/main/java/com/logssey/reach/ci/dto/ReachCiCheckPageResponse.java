package com.logssey.reach.ci.dto;

import java.util.List;

/** CI 검사 목록 커서 페이지 (Reach API 명세 2-4). 항목은 결과 조회(API-12 GET)와 같은 모양. totalCount는 include=total일 때만 준다 */
public record ReachCiCheckPageResponse(
        List<ReachCiCheckResponse> items,
        String nextCursor,
        boolean hasNext,
        Long totalCount) {
}
