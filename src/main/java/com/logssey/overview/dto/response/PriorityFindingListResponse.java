package com.logssey.overview.dto.response;

import java.util.List;

public record PriorityFindingListResponse(List<PriorityFinding> items, long unreviewedCount) {

    /** asset, domain, evidence, recommendation은 null일 수 있다 */
    public record PriorityFinding(
            Long eventId,
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
            String recommendation,
            String sourceType,
            long sourceId,
            String detailPath,
            String assessmentStatus) {
        public PriorityFinding(long eventId, String displayId, String severity, String title,
                AssetRef asset, String environment, String ownerTeam, String reviewStatus,
                String actionStatus, String detectedAt, String domain, String evidence, String recommendation) {
            this(eventId,displayId,severity,title,asset,environment,ownerTeam,reviewStatus,actionStatus,
                    detectedAt,domain,evidence,recommendation,"DETECTION_EVENT",eventId,null,"ASSESSED");
        }
    }

    public record AssetRef(long assetId, String name, String provider, String assetType) {
    }
}
