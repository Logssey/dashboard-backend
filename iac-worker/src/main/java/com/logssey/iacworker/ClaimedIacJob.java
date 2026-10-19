package com.logssey.iacworker;

import java.time.OffsetDateTime;

/** The lease token is unique to this attempt and must accompany every write made for this job. */
public record ClaimedIacJob(long jobId, IacJobKind kind, Long runId, int attemptNo,
                            String leaseToken, OffsetDateTime leaseUntil) {
}
