package com.logssey.secret.response;

import java.time.OffsetDateTime;
import java.util.List;

public record SecretScopeOriginResponse(Long scopeId, Long connectionId, String scopeKey,
                                        String responseOrigin, Long responseOriginVersion,
                                        Long classifiedByUserId, OffsetDateTime classifiedAt,
                                        List<String> allowedOrigins,
                                        List<SecretScopeOriginDecision> history) {
}
