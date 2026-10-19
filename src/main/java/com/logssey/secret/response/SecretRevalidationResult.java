package com.logssey.secret.response;

import java.time.OffsetDateTime;

public record SecretRevalidationResult(long revalidationId, long occurrenceId, long runId,
                                       String jobStatus, String result, String failureCode,
                                       OffsetDateTime requestedAt, OffsetDateTime finishedAt) {
}
