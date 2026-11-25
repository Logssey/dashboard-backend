package com.logssey.overview.score;

import java.util.List;
import java.util.Map;

/**
 * GET /api/v1/overview/score (dashboard-design-docs ADR-D012).
 * score는 1~100 정수이고, 평가된 자산이 하나도 없으면 null("—")이다. coverage는 평가 범위 %(정수).
 * 시각은 ISO-8601 문자열이다
 */
public record SecurityScoreResponse(
        Integer score,
        String scoreRule,
        String configVersion,
        String calculatedAt,
        int coverage,
        Indicators indicators,
        List<Area> areas,
        List<AssetScore> assets,
        List<Part> parts) {

    /**
     * 점수 옆 지표 (ADR-D012 결정 6). gradeDistribution은 열린 건수(LOW·UNASSESSED 포함).
     * riskAccepted는 수용 건수를 넘기는 기능이 없으면 null, deadlineComplianceRate는 닫힌 이력을 아직 모아 두지 않아 null이다
     */
    public record Indicators(long openCritical, long overdue, long unassessed, long unclassified, Long riskAccepted,
                             Integer deadlineComplianceRate, List<String> staleAssets, Map<String, Long> gradeDistribution) {}

    /** 영역별 점수. 평가된 자산이 없는 영역은 score null */
    public record Area(String area, String label, Integer score) {}

    /**
     * 자산 하나. status: EVALUATED · STALE(평가 끊김) · NOT_EVALUATED(평가 안 됨).
     * score는 100 − deduction이고 평가 안 됨이면 null. worst는 감점을 정한 열린 위험(없으면 null)
     */
    public record AssetScore(String id, String name, int tier, int weight, String area, String status, Integer score,
                             int deduction, String lastEvaluatedAt, Worst worst, int openCount) {}

    public record Worst(String part, String title, String grade, int deduction) {}

    /**
     * 기능별 반영 현황. penalty는 그 기능의 열린 위험만으로 같은 식을 계산한 감점이다(평가 끊김 바닥값 제외).
     * 기능별 값을 더해도 전체 감점과 같지 않다(감점을 누적하지 않으므로)
     */
    public record Part(String part, String label, String status, String lastSuccessAt, int openCount, int penalty) {}
}
