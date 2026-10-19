package com.logssey.secret.response;

import java.time.OffsetDateTime;

public record SecretCaseStageChange(String fromStatus, String toStatus, String reasonCode,
                                    long actorUserId, OffsetDateTime changedAt,
                                    long caseVersion) {
}
