package com.logssey.reach.query;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

/**
 * 목록 커서. 마지막 행의 정렬 키 6개와 필터 지문을 Base64로 감싼다 (API 명세 2-4: 불투명 문자열).
 * 배포 순위를 넣기 전(키 5개)의 커서는 400이다. 화면은 처음부터 다시 받는다
 */
record ReachFindingCursor(
    int deploymentRank,
    int statusRank,
    int severityRank,
    int cveYear,
    int cveNumber,
    long findingId,
    int filter
){
    String encode() {
        String raw = deploymentRank + "," + statusRank + "," + severityRank + "," + cveYear + "," + cveNumber + ","
                + findingId + "," + filter;
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    static ReachFindingCursor decode(String value) {
        try {
            String[] p = new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8).split(",");
            if (p.length != 7) throw new IllegalArgumentException();
            return new ReachFindingCursor(Integer.parseInt(p[0]), Integer.parseInt(p[1]), Integer.parseInt(p[2]),
                    Integer.parseInt(p[3]), Integer.parseInt(p[4]), Long.parseLong(p[5]), Integer.parseInt(p[6]));
        } catch (IllegalArgumentException e) {   // Base64 오류, 숫자 오류(NumberFormatException) 모두 여기로
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
    }
}
