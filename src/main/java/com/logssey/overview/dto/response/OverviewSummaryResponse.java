package com.logssey.overview.dto.response;

public record OverviewSummaryResponse(
        long unreviewedCriticalCount,
        long totalCount,
        long unreviewedCount,
        long connectedAssetCount,
        int securityScore,
        String scoreRule,
        String lastCollectedAt,
        SecretIntegration secretIntegration) {
    public record SecretIntegration(String status, String unit, String origin, Long total,
            Long unassessedCount, Long notApplicableCount, boolean restrictedCoverage) {}
}
