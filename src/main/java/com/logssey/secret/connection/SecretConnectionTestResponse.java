package com.logssey.secret.connection;

import java.time.OffsetDateTime;

/** A connection probe result. Provider identifiers and credential references stay server-side. */
public record SecretConnectionTestResponse(long connectionId, String provider, String status,
                                           String reasonCode, OffsetDateTime checkedAt) {
    @com.fasterxml.jackson.annotation.JsonProperty("checkKind")
    public String checkKind() { return "IDENTITY_OR_INSTALLATION"; }
}
