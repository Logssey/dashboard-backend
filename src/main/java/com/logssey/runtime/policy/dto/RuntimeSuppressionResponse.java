package com.logssey.runtime.policy.dto;

public record RuntimeSuppressionResponse(
        long suppressionId,
        String ruleKey,
        String clusterId,
        String namespace,
        String workloadName,
        String processExecutable,
        String targetNamePrefix,
        String operation,
        String reasonCode,
        String evidenceRef,
        String comment,
        long createdByUserId,
        String createdAt,
        String expiresAt,
        Long revokedByUserId,
        String revokedAt,
        String revokeReason,
        String status,
        long version) {
}
