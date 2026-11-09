package com.logssey.reach.rule;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

/**
 * 규칙·취약 함수 목록 커서 (명세 2-4: 불투명 문자열). 데이터가 기동 때 읽은 고정 목록이라 다음 위치(offset)만 담는다.
 * fingerprint에 필터와 데이터 버전을 넣어, 필터를 바꾸거나 데이터 파일이 바뀐 뒤의 커서는 400으로 거절한다
 */
record ReachDataCursor(int offset, int fingerprint) {

    String encode() {
        String raw = offset + "," + fingerprint;
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    static ReachDataCursor decode(String value) {
        try {
            String[] p = new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8).split(",");
            if (p.length != 2) throw new IllegalArgumentException();
            int offset = Integer.parseInt(p[0]);
            if (offset < 1) throw new IllegalArgumentException();
            return new ReachDataCursor(offset, Integer.parseInt(p[1]));
        } catch (IllegalArgumentException e) {   // Base64 오류, 숫자 오류(NumberFormatException) 모두 여기로
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
    }
}
