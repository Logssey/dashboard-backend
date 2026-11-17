package com.logssey.compliance;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

public final class ComplianceJobDtos {
    private ComplianceJobDtos() {}

    public record ScanScope(List<String> regions, List<String> services, List<String> checks) {}
    public record CreateJobRequest(String targetKey, String environment, ScanScope scope) {}
    public record CreateJobResponse(long jobId, String status) {}
    public record CancelJobResponse(long jobId, String status) {}

    public record JobSummary(long jobId, String targetKey, String targetName, String jobKind,
                             String environment, String provider, String status, ScanScope scope,
                             int attemptCount, int maxAttempts, String requestedBy, String errorCode, Long runId,
                             OffsetDateTime createdAt, OffsetDateTime startedAt, OffsetDateTime finishedAt) {}
    public record JobListResponse(List<JobSummary> items) {}

    public record ScopeCatalogResponse(String provider, boolean executionEnabled, boolean connectionTestsEnabled,
                                       String prowlerVersion, String commit,
                                       List<String> services, List<ProwlerScopeCatalog.Check> checks) {}

    public record ClaimRequest(String workerId) {}
    public record TargetIdentity(String targetKey, String awsAccountId, String roleArn, String externalId,
                                 long targetVersion) {}
    public record ClaimedJob(long jobId, String jobKind, String environment, ScanScope scope,
                             TargetIdentity target, UUID leaseToken, long leaseGeneration,
                             OffsetDateTime leaseUntil, String prowlerVersion) {}
    public record LeaseRequest(UUID leaseToken, long leaseGeneration) {}
    public record LeaseResponse(OffsetDateTime leaseUntil) {}
    public record FailureRequest(UUID leaseToken, long leaseGeneration, String errorCode, boolean retryable) {}
    public record CompletionResponse(long jobId, long runId, String status) {}
    public record ConnectionCompletionRequest(UUID leaseToken, long leaseGeneration,
                                              String accountId, String callerArn) {}
    public record ConnectionCompletionResponse(long jobId, String targetKey, String status) {}
}
