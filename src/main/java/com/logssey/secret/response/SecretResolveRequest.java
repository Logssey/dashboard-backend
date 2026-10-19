package com.logssey.secret.response;

public record SecretResolveRequest(Long expectedVersion, String reasonCode) {
}
