package com.logssey.complianceworker;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

final class WorkerDtos {
    private WorkerDtos() {}

    record ScanScope(List<String> regions, List<String> services, List<String> checks) {}
    record TargetIdentity(String targetKey, String awsAccountId, String roleArn, String externalId,
                          long targetVersion) {}
    record ClaimedJob(long jobId, String jobKind, String environment, ScanScope scope,
                      TargetIdentity target, UUID leaseToken, long leaseGeneration,
                      OffsetDateTime leaseUntil, String prowlerVersion) {}
    record LeaseResponse(OffsetDateTime leaseUntil) {}
    record AwsCallerIdentity(String accountId, String arn) {}
}
