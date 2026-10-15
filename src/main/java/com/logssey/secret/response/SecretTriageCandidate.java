package com.logssey.secret.response;

public record SecretTriageCandidate(Long secretId, String maskedLabel, String issuer,
                                    String credentialType, String componentState,
                                    Long occurrenceCount) {
}
