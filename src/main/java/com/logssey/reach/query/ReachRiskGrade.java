package com.logssey.reach.query;

import java.math.BigDecimal;

import com.logssey.reach.query.dto.ReachFindingRisk;

/**
 * 통합 현황 보안 점수에 쓰는 이미지 등급과 감점 (dashboard-design-docs ADR-D012 결정 1 "이미지 등급", 초안 v0 §7.3).
 * Reach는 스캐너 심각도만 저장하므로, 가능성(도달 × 실행) × 영향(스캐너 심각도)을 OWASP 3×3으로 묶어 등급을 정한다.
 * 분석 안 함(NOT_ANALYZED)은 닿지 않는다고 보지도, 닿는다고 확정하지도 않아 "도달 미확인"(UNKNOWN과 같은 줄)으로 본다.
 * 감점은 등급 구간(CRITICAL 74~99, HIGH 48~73, MEDIUM 22~47) 안에서 CVSS 비율로 정한다. LOW와 미평가(스캐너 심각도를 모름)는
 * 감점이 없다(LOW는 점수에 넣지 않고, 미평가를 어떻게 셀지는 통합 현황이 정한다)
 */
public final class ReachRiskGrade {

    public static final String UNASSESSED = "UNASSESSED";

    private ReachRiskGrade() {}

    /**
     * @param severity   스캐너 심각도 (CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN)
     * @param status     현재 판정 (사람 판정이 있으면 그것). REACHABLE / UNKNOWN / UNREACHABLE / NOT_ANALYZED(도달 미확인으로 본다)
     * @param deployment 운영 실행 여부 (RUNNING / NOT_RUNNING / UNKNOWN)
     * @param cvss       CVSS v3 기본 점수. 없으면 null
     */
    public static ReachFindingRisk of(String severity, String status, String deployment, BigDecimal cvss) {
        // 닿지 않음은 영향과 관계없이 LOW(보류)
        if ("UNREACHABLE".equals(status)) return new ReachFindingRisk("LOW", null, null);
        int impact = impact(severity);
        // 영향(스캐너 심각도)을 모르면 미평가. 분석 안 함(NOT_ANALYZED)은 아래에서 도달 미확인으로 계산한다
        if (impact < 0) return new ReachFindingRisk(UNASSESSED, null, null);

        boolean reachable = "REACHABLE".equals(status);
        boolean running = "RUNNING".equals(deployment);
        // 닿음 + 실행 중 = HIGH, 닿음 + 실행 미확인 또는 도달 미확인 + 실행 중 = MEDIUM, 나머지(도달 미확인 + 실행 미확인) = LOW.
        // 도달 미확인 = UNKNOWN, NOT_ANALYZED
        int likelihood = reachable && running ? 2 : reachable || running ? 1 : 0;
        // 3×3: 둘 다 HIGH면 CRITICAL, 합이 3이면 HIGH, 2면 MEDIUM, 그 아래는 LOW
        int sum = likelihood + impact;
        String grade = sum == 4 ? "CRITICAL" : sum == 3 ? "HIGH" : sum == 2 ? "MEDIUM" : "LOW";
        return new ReachFindingRisk(grade, LEVELS[likelihood], deduction(grade, impact, cvss));
    }

    private static final String[] LEVELS = {"LOW", "MEDIUM", "HIGH"};

    /** 스캐너 심각도 → 영향 0(LOW)·1(MEDIUM)·2(HIGH). 모르면 -1 */
    private static int impact(String severity) {
        if (severity == null) return -1;
        return switch (severity) {
            case "CRITICAL", "HIGH" -> 2;
            case "MEDIUM" -> 1;
            case "LOW" -> 0;
            default -> -1;
        };
    }

    /** 영향 단계마다 그 스캐너 심각도의 CVSS v3 범위 (FIRST CVSS v3 등급표) */
    private static final double[][] CVSS_RANGE = {{0.1, 3.9}, {4.0, 6.9}, {7.0, 10.0}};

    /**
     * 등급 구간 안에서 CVSS 비율만큼. 구간 아래 + (CVSS − 범위 아래) ÷ 범위 폭 × 25.
     * CVSS가 없으면 구간 맨 위 값이고, 범위를 벗어나면(심각도와 CVSS 출처가 다를 때) 구간 끝으로 자른다
     */
    static Integer deduction(String grade, int impact, BigDecimal cvss) {
        int top = switch (grade) {
            case "CRITICAL" -> 99;
            case "HIGH" -> 73;
            case "MEDIUM" -> 47;
            default -> -1;
        };
        if (top < 0) return null;
        if (cvss == null) return top;
        double[] range = CVSS_RANGE[impact];
        double ratio = (cvss.doubleValue() - range[0]) / (range[1] - range[0]);
        ratio = Math.max(0, Math.min(1, ratio));
        return (int) Math.round(top - 25 + ratio * 25);
    }
}
