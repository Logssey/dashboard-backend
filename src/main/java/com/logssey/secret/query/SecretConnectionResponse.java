package com.logssey.secret.query;

public record SecretConnectionResponse(
        long connectionId,
        String provider,
        String displayName,
        String status,
        long approvedScopeCount) {
}
