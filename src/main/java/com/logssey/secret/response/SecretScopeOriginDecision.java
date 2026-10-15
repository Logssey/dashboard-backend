package com.logssey.secret.response;

import java.time.OffsetDateTime;

public record SecretScopeOriginDecision(String fromOrigin, String toOrigin, String reasonCode,
                                        Long actorUserId, OffsetDateTime decidedAt, Long version) {
}
