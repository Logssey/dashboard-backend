package com.logssey.secret.response;

import java.util.List;

public record SecretOccurrenceTriageResponse(Long occurrenceId, Long secretId, Long connectionId,
                                             Long scopeId, String componentState, String exposureStatus,
                                             String presenceStatus, Long assessmentVersion,
                                             String scopeOrigin, Long scopeOriginVersion, Long openCaseId,
                                             List<SecretTriageFinding> findings,
                                             List<SecretExposureAssessment> history) {
}
