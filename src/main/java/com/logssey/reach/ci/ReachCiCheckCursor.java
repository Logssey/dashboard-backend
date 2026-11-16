package com.logssey.reach.ci;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

/** CI 검사 목록 커서. 마지막 행의 검사 id와 필터 지문을 Base64로 감싼다 (API 명세 2-4: 불투명 문자열). 정렬은 최신(id 큰) 순 하나 */
record ReachCiCheckCursor(long checkId, int filter) {

    String encode() {
        String raw = checkId + "," + filter;
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    static ReachCiCheckCursor decode(String value) {
        try {
            String[] p = new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8).split(",");
            if (p.length != 2) throw new IllegalArgumentException();
            return new ReachCiCheckCursor(Long.parseLong(p[0]), Integer.parseInt(p[1]));
        } catch (IllegalArgumentException e) {   // Base64 오류, 숫자 오류(NumberFormatException) 모두 여기로
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
    }
}
