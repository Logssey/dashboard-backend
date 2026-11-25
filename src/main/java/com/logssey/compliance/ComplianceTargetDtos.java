package com.logssey.compliance;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;

public final class ComplianceTargetDtos {
    private ComplianceTargetDtos() {}

    public record CreateTargetRequest(String targetKey, String displayName, String awsAccountId,
                                      String roleArn, List<String> defaultRegions,
                                      AssessmentProfile assessmentProfile) {}

    public record UpdateTargetRequest(long expectedVersion, String displayName, String awsAccountId,
                                      String roleArn, List<String> defaultRegions, Boolean enabled,
                                      AssessmentProfile assessmentProfile) {}

    public record AssessmentProfile(int schemaVersion, Map<String, String> serviceUsage,
                                    Map<String, String> requirements) {
        public static AssessmentProfile empty() {
            return new AssessmentProfile(1, Map.of(), Map.of());
        }
    }

    public record TargetSummary(String targetKey, String displayName, String provider, String awsAccountId,
                                String roleArn, String externalId, List<String> defaultRegions, boolean enabled,
                                AssessmentProfile assessmentProfile,
                                String connectionStatus, String connectionErrorCode,
                                OffsetDateTime connectionCheckedAt, long version,
                                OffsetDateTime createdAt, OffsetDateTime updatedAt) {}

    public record TargetListResponse(List<TargetSummary> items) {}

    public record ConnectionTestResponse(long jobId, String status) {}

    record TargetExecutionSnapshot(String targetKey, String awsAccountId, String roleArn,
                                   String externalId, List<String> defaultRegions, long version, boolean enabled,
                                   String connectionStatus, AssessmentProfile assessmentProfile) {}
}
