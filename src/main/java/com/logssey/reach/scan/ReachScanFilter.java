package com.logssey.reach.scan;

import java.time.Instant;
import java.util.List;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachCodes;

/**
 * 스캔 이력(API-02) 필터와 정렬. 쿼리 파라미터 이름을 그대로 칸 이름으로 쓴다.
 * 한 칸 안의 값은 OR, 칸끼리는 AND. from은 포함, to는 미포함. 허용 밖 값이면 만들 때 INVALID_INPUT(400)이다.
 */
record ReachScanFilter(
        Long target,
        List<String> scanStatus,
        List<String> trigger,
        Instant from,
        Instant to,
        String sort) {

    ReachScanFilter {
        scanStatus = ReachCodes.checked(scanStatus, ReachCodes.SCAN_STATUSES);
        trigger = ReachCodes.checked(trigger, ReachCodes.TRIGGERS);
        sort = sort == null ? "-createdAt" : sort;
        if (!ReachCodes.SCAN_SORTS.contains(sort)) throw new ApiException(ErrorCode.INVALID_INPUT);
        if (from != null && to != null && from.isAfter(to)) throw new ApiException(ErrorCode.INVALID_INPUT);
    }

    /** 커서가 이 필터·정렬로 만들어졌는지 확인하는 값. 커서와 함께 필터나 정렬을 바꾸면 400이다 (명세 2-4) */
    int fingerprint() {
        return toString().hashCode();
    }
}
