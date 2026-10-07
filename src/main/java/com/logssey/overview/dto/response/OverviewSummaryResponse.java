package com.logssey.overview.dto.response;

public record OverviewSummaryResponse(
        long unreviewedCriticalCount,
        long totalCount,
        long unreviewedCount,
        long connectedAssetCount,
        int securityScore,
        String scoreRule,
        String lastCollectedAt) {
}
