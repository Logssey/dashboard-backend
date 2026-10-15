package com.logssey.secret.response;

import java.time.OffsetDateTime;

public record SecretTriageFinding(Long findingId, String ruleId, OffsetDateTime detectedAt) {
}
