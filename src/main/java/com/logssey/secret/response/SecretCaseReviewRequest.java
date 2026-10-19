package com.logssey.secret.response;

public record SecretCaseReviewRequest(String decision, String reasonCode, Long expectedVersion) {
}
