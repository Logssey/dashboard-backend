package com.logssey.credential.event;

import java.time.Instant;

/** detection_events에 새로 넣을 한 건 */
public record NewDetectionEvent(
        Long assetId,
        long credentialId,
        String displayId,
        String severity,
        String title,
        String environment,
        String ownerTeam,
        Instant detectedAt,
        String domain,
        String evidence,
        String recommendation) {
}
