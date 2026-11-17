package com.logssey.compliance;

import java.time.OffsetDateTime;
import java.util.List;

public final class ComplianceTargetDtos {
    private ComplianceTargetDtos() {}

    public record CreateTargetRequest(String targetKey, String displayName, String awsAccountId,
                                      String roleArn, List<String> defaultRegions) {}

    public record UpdateTargetRequest(long expectedVersion, String displayName, String awsAccountId,
                                      String roleArn, List<String> defaultRegions, Boolean enabled) {}

    public record TargetSummary(String targetKey, String displayName, String provider, String awsAccountId,
                                String roleArn, String externalId, List<String> defaultRegions, boolean enabled,
                                String connectionStatus, String connectionErrorCode,
                                OffsetDateTime connectionCheckedAt, long version,
                                OffsetDateTime createdAt, OffsetDateTime updatedAt) {}

    public record TargetListResponse(List<TargetSummary> items) {}

    public record ConnectionTestResponse(long jobId, String status) {}

    record TargetExecutionSnapshot(String targetKey, String awsAccountId, String roleArn,
                                   String externalId, List<String> defaultRegions, long version, boolean enabled,
                                   String connectionStatus) {}
}
