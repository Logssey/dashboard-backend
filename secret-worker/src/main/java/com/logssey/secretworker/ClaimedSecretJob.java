package com.logssey.secretworker;

import java.time.OffsetDateTime;

/** The lease token is unique to this attempt and must accompany every write made for this job. */
public record ClaimedSecretJob(long jobId, long runId, long connectionId, int attemptNo,
                               String leaseToken, OffsetDateTime leaseUntil,
        long leaseGeneration) {
    public ClaimedSecretJob(
            long jobId,
            long runId,
            long connectionId,
            int attemptNo,
            String token,
            OffsetDateTime until) {
        this(jobId, runId, connectionId, attemptNo, token, until, attemptNo);
}
}
