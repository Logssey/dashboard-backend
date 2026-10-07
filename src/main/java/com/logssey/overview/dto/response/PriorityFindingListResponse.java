package com.logssey.overview.dto.response;

import java.util.List;

public record PriorityFindingListResponse(List<PriorityFinding> items, long unreviewedCount) {

    /** asset, domain, evidence, recommendation은 null일 수 있다 */
    public record PriorityFinding(
            long eventId,
            String displayId,
            String severity,
            String title,
            AssetRef asset,
            String environment,
            String ownerTeam,
            String reviewStatus,
            String actionStatus,
            String detectedAt,
            String domain,
            String evidence,
            String recommendation) {
    }

    public record AssetRef(long assetId, String name, String provider, String assetType) {
    }
}
