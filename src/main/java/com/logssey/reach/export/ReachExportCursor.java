package com.logssey.reach.export;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

/** OCSF 내보내기 커서. 마지막 Finding id와 필터 지문을 Base64로 감싼다 (API 명세 2-4: 불투명 문자열) */
record ReachExportCursor(long findingId, int filter) {

    String encode() {
        String raw = findingId + "," + filter;
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    static ReachExportCursor decode(String value) {
        try {
            String[] p = new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8).split(",");
            if (p.length != 2) throw new IllegalArgumentException();
            return new ReachExportCursor(Long.parseLong(p[0]), Integer.parseInt(p[1]));
        } catch (IllegalArgumentException e) {   // Base64 오류, 숫자 오류(NumberFormatException) 모두 여기로
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
    }
}
