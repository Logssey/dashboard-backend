package com.logssey.reach.query.dto;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

/** API-08 요약. 필드 이름은 프론트 src/api/reach.ts 의 ReachSummary 와 같다 */
public record ReachSummaryResponse(
    Scope scope,
    Basis basis,
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
        public record Scope(Long targetId, Long scanId){}
        /**
         * 기본 범위(target·scanId 없음)일 때만 준다. requested는 요청한 기준, applied는 실제로 쓴 기준이다
         * (RUNNING을 요청해도 L1이 꺼졌거나 신선한 조회가 없으면 LATEST). scans는 쓴 스캔, unscannedRunning은
         * 실행 중인데 PR이 아닌 성공 스캔이 없는 워크로드(그 앱은 최신 스캔으로 대신 집계됐다)
         */
        public record Basis(String requested, String applied, List<ScopeScan> scans, List<UnscannedWorkload> unscannedRunning){}
        public record ScopeScan(String app, String targetType, long targetId, long scanId, String imageDigest, boolean running){}
        public record UnscannedWorkload(String app, String namespace, String name, String container,
                                        String imageRepository, String imageDigest){}
        public record Totals(long findings){}
        public record NoiseReduction(long unreachable, long judged, Double ratio){}
        public record Coverage(long judged, long total, Double ratio){}
    }