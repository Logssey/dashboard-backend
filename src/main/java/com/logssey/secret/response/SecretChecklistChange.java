package com.logssey.secret.response;

import java.time.OffsetDateTime;

public record SecretChecklistChange(long itemId, String fromStatus, String toStatus,
                                    String evidenceRef, long changedByUserId,
                                    OffsetDateTime changedAt, long caseVersion) {
}
