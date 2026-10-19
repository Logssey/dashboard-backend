package com.logssey.secret.response;

import java.time.OffsetDateTime;

public record SecretActionRequest(String actionType, Long occurrenceId,
                                  OffsetDateTime performedAt, String evidenceRef,
                                  Long expectedVersion) {
}
