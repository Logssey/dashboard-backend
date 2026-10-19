package com.logssey.iac.run;

import java.time.OffsetDateTime;

public record IacRunStatusResponse(long runId, String repo, Integer prNumber, String headSha, String status,
                                   String verdict, String highestSeverity, OffsetDateTime graphAsOf,
                                   OffsetDateTime createdAt, OffsetDateTime finishedAt) {
}
