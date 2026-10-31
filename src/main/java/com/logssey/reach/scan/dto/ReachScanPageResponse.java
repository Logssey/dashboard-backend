package com.logssey.reach.scan.dto;

import java.util.List;

/** 스캔 이력 커서 페이지 (Reach API 명세 2-4). totalCount는 include=total일 때만 준다 */
public record ReachScanPageResponse(
        List<ReachScanResponse> items,
        String nextCursor,
        boolean hasNext,
        Long totalCount) {
}
