package com.logssey.reach.query;

import java.util.List;

import com.logssey.reach.ReachCodes;


/**
 * Finding 목록(API-04) 필터. 쿼리 파라미터 이름을 그대로 칸 이름으로 쓴다 (Reach API 명세 2-5).
 * 한 칸 안의 값은 OR, 칸끼리는 AND. 허용 밖 값이면 만들 때 INVALID_INPUT(400)이다.
 */
record ReachFindingFilter(
        List<String> status,
        List<String> severity,
        List<String> reviewState,
        List<String> deployment,
        String cveContains) {

    ReachFindingFilter {
        status = ReachCodes.checked(status, ReachCodes.STATUSES);
        severity = ReachCodes.checked(severity, ReachCodes.SEVERITIES);
        reviewState = ReachCodes.checked(reviewState, ReachCodes.REVIEW_STATES);
        deployment = ReachCodes.checked(deployment, ReachCodes.DEPLOYMENTS);
        cveContains = (cveContains == null || cveContains.isBlank()) ? null : cveContains.trim();
    }

    /** 커서가 이 필터로 만들어졌는지 확인하는 값. 커서와 함께 필터를 바꾸면 400이다 (명세 2-4) */
    int fingerprint() {
        return toString().hashCode();
    }
}