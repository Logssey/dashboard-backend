package com.logssey.runtime.policy.dto;

import java.time.Instant;

public record RuntimeSuppressionCreateRequest(
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
        Instant expiresAt,
        String idempotencyKey) {
}
