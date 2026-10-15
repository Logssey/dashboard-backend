package com.logssey.secret.response;

public record SecretScopeOriginRequest(String origin, String reasonCode, Long expectedVersion) {
}
