package com.logssey.complianceworker;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

final class WorkerDtos {
    private WorkerDtos() {}

    record ScanScope(List<String> regions, List<String> services, List<String> checks) {}
    record ClaimedJob(long jobId, String environment, ScanScope scope, UUID leaseToken,
                      long leaseGeneration, OffsetDateTime leaseUntil, String prowlerVersion) {}
    record LeaseResponse(OffsetDateTime leaseUntil) {}
}
