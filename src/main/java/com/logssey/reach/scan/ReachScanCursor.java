package com.logssey.reach.scan;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

/** 스캔 이력 커서. 마지막 행의 정렬 키, 스캔 id, 필터 지문을 Base64로 감싼다 (API 명세 2-4: 불투명 문자열) */
record ReachScanCursor(long sortKey, long scanId, int filter) {

    String encode() {
        String raw = sortKey + "," + scanId + "," + filter;
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    static ReachScanCursor decode(String value) {
        try {
            String[] p = new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8).split(",");
            if (p.length != 3) throw new IllegalArgumentException();
            return new ReachScanCursor(Long.parseLong(p[0]), Long.parseLong(p[1]), Integer.parseInt(p[2]));
        } catch (IllegalArgumentException e) {   // Base64 오류, 숫자 오류(NumberFormatException) 모두 여기로
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
    }
}
