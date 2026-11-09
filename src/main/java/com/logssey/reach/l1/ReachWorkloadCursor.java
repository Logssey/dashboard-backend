package com.logssey.reach.l1;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

/**
 * 워크로드 목록 커서. 마지막 항목의 정렬 키 5개와 필터 지문을 감싼다 (API 명세 2-4: 불투명 문자열).
 * 정렬 키가 문자열이라 칸마다 따로 Base64로 바꾼 뒤 '.'으로 잇는다(이름에 어떤 글자가 와도 안 깨진다).
 * id는 업로드마다 바뀌어서 키로 쓰지 않는다. 그래서 페이지 사이에 업로드가 있어도 이어 받을 수 있다
 */
record ReachWorkloadCursor(
        String namespace,
        String name,
        String kind,
        String container,
        String digest,
        int filter) {

    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    String encode() {
        return String.join(".", part(namespace), part(name), part(kind), part(container), part(digest),
                part(Integer.toString(filter)));
    }

    static ReachWorkloadCursor decode(String value) {
        try {
            String[] p = value.split("\\.", -1);
            if (p.length != 6) throw new IllegalArgumentException();
            return new ReachWorkloadCursor(text(p[0]), text(p[1]), text(p[2]), text(p[3]), text(p[4]),
                    Integer.parseInt(text(p[5])));
        } catch (IllegalArgumentException e) {   // Base64 오류, 숫자 오류(NumberFormatException) 모두 여기로
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
    }

    private static String part(String text) {
        return ENCODER.encodeToString(text.getBytes(StandardCharsets.UTF_8));
    }

    private static String text(String part) {
        return new String(DECODER.decode(part), StandardCharsets.UTF_8);
    }
}
