package com.logssey.secret.response;

public record SecretCaseOpenRequest(Long occurrenceId, String reason,
                                    Long expectedAssessmentVersion,
                                    Long expectedScopeOriginVersion) {
}
