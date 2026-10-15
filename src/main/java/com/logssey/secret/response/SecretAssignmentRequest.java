package com.logssey.secret.response;

public record SecretAssignmentRequest(String team, Long assigneeUserId, String reason,
                                      Long expectedVersion) {
}
