package com.logssey.overview.dto.response;

import java.util.List;

public record OverviewSummaryResponse(
        long unreviewedCriticalCount,
        long totalCount,
        long unreviewedCount,
        long connectedAssetCount,
        int securityScore,
        String scoreRule,
        String lastCollectedAt,
        SecretIntegration secretIntegration,
        List<PartSummary> parts) {
    public record SecretIntegration(String status, String unit, String origin, Long total,
            Long unassessedCount, Long notApplicableCount, boolean restrictedCoverage) {}

    /**
     * 보안 기능별 반영 현황 (같은 원인을 묶은 건수). status: CONNECTED · NO_DATA · NOT_AUTHORIZED · ERROR.
     * unassessed 는 미평가·평가 대상 외, penalty 는 점수에서 깎인 점수
     */
    public record PartSummary(String part, String label, String status, String link, long critical, long high,
            long medium, long low, long unassessed, long total, long penalty, String dataAsOf) {}
}
