package com.logssey.secret.response;

public record SecretRevalidationRequest(Long occurrenceId, Long expectedVersion,
                                        String idempotencyKey) {
}
