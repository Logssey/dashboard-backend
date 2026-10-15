package com.logssey.secret.response;

public record SecretExposureAssessmentRequest(String decision, String reasonCode,
                                              Long findingId, Long expectedVersion) {
}
