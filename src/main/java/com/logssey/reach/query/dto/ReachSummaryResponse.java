package com.logssey.reach.query.dto;

import java.time.OffsetDateTime;
import java.util.Map;

/** API-08 요약. 필드 이름은 프론트 src/api/reach.ts 의 ReachSummary 와 같다 */
public record ReachSummaryResponse(
    Scope scope,
    Totals totals,
    Map<String, Long> byStatus,
    Map<String, Long> byNotAnalyzedReason,
    Map<String, Long> bySeverity,
    Map<String, Long> byMethod,
    Map<String, Long> byReviewState,
    Map<String, Long> byDeployment,
    Map<String, Map<String, Long>> severityByStatus,
    NoiseReduction noiseReduction,
    Coverage coverage,
    OffsetDateTime generatedAt) {
        public record Scope(Long targetId, Long ScanId){}
        public record Totals(long findings){}
        public record NoiseReduction(long unreachable, long judged, Double ratio){}
        public record Coverage(long judged, long total, Double ratio){}
    }