package com.logssey.iac.query;

import java.util.List;

/**
 * S-01 C 경로 상세. cutPoints 는 이 경로를 끊을 수 있는 관계와 조치 (API 계약 action 값).
 * 끊긴 관계(닫힌 경로가 왜 닫혔는지)는 아직 기록하지 않는다.
 */
public record IacPathDetailResponse(IacPathResponse path, List<CutPoint> cutPoints) {

    /** fromHop·toHop 은 hops 의 순번 (0 = 인터넷). */
    public record CutPoint(int fromHop, int toHop, String action, String templateKey) {
    }
}
