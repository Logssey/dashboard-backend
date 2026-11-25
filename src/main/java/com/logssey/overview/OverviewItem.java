package com.logssey.overview;

import java.time.Instant;
import java.util.Locale;

/**
 * 통합 현황이 세는 위험 한 건. 같은 part·groupKey 는 같은 원인이라 한 건으로 묶는다
 * (예: 같은 데이터 자산까지 가는 IaC 경로들, 여러 이미지의 같은 CVE·패키지, 여러 자원의 같은 점검 항목).
 *
 * @param severity    CRITICAL · HIGH · MEDIUM · LOW · UNASSESSED · NOT_APPLICABLE
 * @param environment PROD · DEV (환경을 모르는 기능은 운영 클러스터·운영 배포 코드라 PROD)
 * @param needsAction 지금 확인·조치가 필요한가 (각 기능의 "열린" 기준)
 */
public record OverviewItem(OverviewPart part, String groupKey, String severity, String title, String environment,
                           boolean needsAction, Instant firstSeenAt, String detailPath) {

    /** 각 기능의 심각도 표기를 공통 등급으로. 모르는 값은 미평가 */
    public static String severity(String raw) {
        if (raw == null) return "UNASSESSED";
        return switch (raw.trim().toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> "CRITICAL";
            case "HIGH" -> "HIGH";
            case "MEDIUM" -> "MEDIUM";
            case "LOW", "INFORMATIONAL", "INFO" -> "LOW";
            case "NOT_APPLICABLE" -> "NOT_APPLICABLE";
            default -> "UNASSESSED";
        };
    }

    /** 낮을수록 위험 (정렬·묶을 때 높은 쪽을 고른다) */
    public static int rank(String severity) {
        return switch (severity == null ? "" : severity) {
            case "CRITICAL" -> 0;
            case "HIGH" -> 1;
            case "MEDIUM" -> 2;
            case "LOW" -> 3;
            case "UNASSESSED" -> 4;
            default -> 5;
        };
    }
}
