package com.logssey.secret.response;

public record SecretResumeRequest(Long occurrenceId, Long expectedVersion,
                                  String reasonCode) {
}
