package com.logssey.iac.query;

import java.time.OffsetDateTime;

import tools.jackson.databind.JsonNode;

/**
 * S-01 F State (API 계약 GET /state/summary).
 * tfstate 는 [{arn, name, readers: [{kind, name}]}]. 버킷 정책·민감 후보·실제 수는 아직 확인하지 않아 null.
 */
public record IacStateSummaryResponse(OffsetDateTime checkedAt, long readerCount, JsonNode tfstate,
                                      JsonNode bucketPolicy, Long sensitiveCandidates, Long sensitiveActual) {
}
