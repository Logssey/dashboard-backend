package com.logssey.reach.export.dto;

import java.util.List;

/** OCSF 내보내기 커서 페이지 (Reach API 명세 2-4, API-11). 이 API는 include=total을 받지 않는다 */
public record ReachOcsfPageResponse(
        List<ReachOcsfFindingResponse> items,
        String nextCursor,
        boolean hasNext) {
}
