package com.logssey.iac.query;

import java.time.OffsetDateTime;
import java.util.Map;

/**
 * S-01 A·B. 아직 계산하지 않는 지표(State 속 시크릿)와, main 점검 기록이 없을 때의 main 기준 plan 전 검사 위반은 null.
 * severityCounts 는 열린 경로와 매일 점검 발견 건만 센다 (열린 PR 결과는 제외).
 */
public record IacSummaryResponse(Metrics metrics, Map<String, Long> severityCounts,
                                 OffsetDateTime lastFullCheckAt, OffsetDateTime graphAsOf, boolean graphStale) {

    public record Metrics(long tier1OpenPaths, long openPaths, Long drifts, Long stateSecrets, Long gateViolations) {
    }
}
