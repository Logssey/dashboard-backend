package com.logssey.secret.response;

public record SecretCaseOccurrence(long occurrenceId, String responseStatus,
                                   boolean canRequestRevalidation, boolean canResume) {
    SecretCaseOccurrence(long occurrenceId, String responseStatus) {
        this(occurrenceId, responseStatus, false, false);
    }
}
