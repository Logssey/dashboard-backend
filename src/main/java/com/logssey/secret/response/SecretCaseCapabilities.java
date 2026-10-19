package com.logssey.secret.response;

public record SecretCaseCapabilities(boolean canReview, boolean canStart,
                                     boolean canUpdateChecklist, boolean canRecordAction,
                                     boolean canRequestRevalidation, boolean canResolve,
                                     boolean canResume) {
}
