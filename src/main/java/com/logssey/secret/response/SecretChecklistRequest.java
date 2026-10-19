package com.logssey.secret.response;

public record SecretChecklistRequest(Boolean completed, String guideVersion,
                                     String evidenceRef, Long expectedVersion) {
}
