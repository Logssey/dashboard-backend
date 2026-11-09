package com.logssey.reach.l1.dto;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * API-07 응답. 커서 페이지(명세 2-4)에 네임스페이스별 마지막 조회(observations)를 더한다.
 * observations는 페이지와 관계없이 매번 주고, namespace 필터만 적용한다. 조회 기록이 없으면 빈 배열이다.
 * totalCount는 include=total일 때만 준다
 */
public record ReachWorkloadPageResponse(
        List<Observation> observations,
        List<ReachWorkloadResponse> items,
        String nextCursor,
        boolean hasNext,
        Long totalCount) {

    /** fresh는 observedAt이 신선도(48시간) 안이면 true. Finding deployment 계산과 같은 기준 */
    public record Observation(String cluster, String namespace, OffsetDateTime observedAt, String source,
                              boolean fresh) {
    }
}
