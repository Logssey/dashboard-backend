package com.logssey.secret.response;

import java.time.OffsetDateTime;

public record SecretActionRecord(long actionId, long occurrenceId, String actionType,
                                 OffsetDateTime performedAt, OffsetDateTime recordedAt,
                                 long recordedByUserId, String recordedByName,
                                 String evidenceRef, long caseVersion) {
}
