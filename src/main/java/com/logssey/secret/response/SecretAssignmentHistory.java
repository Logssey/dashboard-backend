package com.logssey.secret.response;

import java.time.OffsetDateTime;

public record SecretAssignmentHistory(OffsetDateTime changedAt, long changedByUserId,
                                      String changedByDisplayName, String previousTeam,
                                      Long previousUserId, String previousAssigneeDisplayName,
                                      String newTeam, Long newUserId, String newAssigneeDisplayName,
                                      String reason) {
}
