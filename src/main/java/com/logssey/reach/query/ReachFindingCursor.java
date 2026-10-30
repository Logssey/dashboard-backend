package com.logssey.reach.query;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

/** 목록 커서. 마지막 행의 정렬 키 5개와 필터 지문을 Base64로 감싼다 (API 명세 2-4: 불투명 문자열) */
record ReachFindingCursor(
    int statusRank,
    int severityRank,
    int cveYear,
    int cveNumber,
    long findingId,
    int filter
){
    String encode() {
        String raw = statusRank + "," + severityRank + "," + cveYear + "," + cveNumber + "," + findingId + "," + filter;
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    static ReachFindingCursor decode(String value) {
        try {
            String[] p = new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8).split(",");
            if (p.length != 6) throw new IllegalArgumentException();
            return new ReachFindingCursor(Integer.parseInt(p[0]), Integer.parseInt(p[1]), Integer.parseInt(p[2]),
                    Integer.parseInt(p[3]), Long.parseLong(p[4]), Integer.parseInt(p[5]));
        } catch (IllegalArgumentException e) {   // Base64 오류, 숫자 오류(NumberFormatException) 모두 여기로
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
    }
}