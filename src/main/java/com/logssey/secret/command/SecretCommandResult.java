package com.logssey.secret.command;
/** Only controlled identifiers and status codes enter persisted command results or audit. */
public record SecretCommandResult(long targetId, long version, Status status) {
    public enum Status { PENDING, RUNNING, SUCCEEDED, PARTIAL, FAILED, SKIPPED, CANCELLED, OPEN, CLOSED, ATTESTED, IN_PROGRESS, REVALIDATION_PENDING }
    @com.fasterxml.jackson.annotation.JsonProperty("requiresSnapshotRefresh")
    public boolean requiresSnapshotRefresh() { return true; }
    public SecretCommandResult {
        if (targetId <= 0 || version < 0 || status == null) throw new IllegalArgumentException("Invalid command result");
    }
}