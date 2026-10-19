package com.logssey.secret.response;

public record SecretCaseStartRequest(String reasonCode, Long expectedVersion) {
}
