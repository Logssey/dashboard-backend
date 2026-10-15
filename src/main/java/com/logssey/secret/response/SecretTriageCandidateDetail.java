package com.logssey.secret.response;

import java.util.List;

public record SecretTriageCandidateDetail(Long secretId, String maskedLabel, String issuer,
                                          String credentialType, String componentState,
                                          List<SecretTriageCandidateOccurrence> occurrences) {
}
