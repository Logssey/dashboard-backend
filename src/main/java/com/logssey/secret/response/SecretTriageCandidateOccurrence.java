package com.logssey.secret.response;

public record SecretTriageCandidateOccurrence(Long id, Long connectionId, Long scopeId,
                                              String sourceObjectRef, String locationKey,
                                              String environment, String exposureStatus,
                                              String presenceStatus, Long assessmentVersion,
                                              String scopeOrigin, Long scopeOriginVersion) {
}
