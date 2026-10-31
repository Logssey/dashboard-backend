package com.logssey.reach.query.dto;

import java.util.List;

/** 커서 페이지 (Reach API 명세 2-4). totalCount 는 include=total 일 때만 준다.  */
public record ReachFindingPageResponse(
    List<ReachFindingResponse> items,
    String nextCursor,
    boolean hasNext,
    Long totalCount) {

    }
