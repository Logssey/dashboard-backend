package com.logssey.secret.response;

import java.time.OffsetDateTime;

public record SecretCaseSummary(long caseId, long secretId, String maskedLabel, String issuer,
                                String credentialType, String caseOrigin, String stage, String assigneeTeam,
                                Long assigneeUserId, String assigneeDisplayName, long version,
                                OffsetDateTime createdAt, OffsetDateTime updatedAt) {
}
