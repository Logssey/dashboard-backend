package com.logssey.secret.command;

/** Only controlled identifiers and status codes enter persisted command results or audit. */
public record SecretCommandResult(long targetId, long version, Status status) {
    public enum Status { PENDING, RUNNING, SUCCEEDED, PARTIAL, FAILED, SKIPPED, CANCELLED }

    public SecretCommandResult {
        if (targetId <= 0 || version < 0 || status == null)
            throw new IllegalArgumentException("Invalid command result");
    }
}
