package com.logssey.secret.response;

import java.util.Map;
import java.util.Set;

/** The only case attributes permitted in an external guide request. */
record SecretGuideContext(String issuer, String credentialType, String componentState,
                          String stage, String validationStatus) {
    private static final Set<String> ISSUERS = Set.of("AWS", "GITHUB", "NOTION");
    private static final Set<String> TYPES = Set.of("AWS_ACCESS_KEY_PAIR", "AWS_TEMPORARY_CREDENTIALS",
            "AWS_IAM_ACCESS_KEY", "GITHUB_CLASSIC_PAT", "GITHUB_FINE_GRAINED_PAT", "NOTION_CONNECTION_TOKEN");
    private static final Set<String> COMPONENT_STATES = Set.of("CONFIRMED", "CANDIDATE", "METADATA_ONLY");
    private static final Set<String> STAGES = Set.of("OPEN", "IN_PROGRESS", "REVALIDATION_PENDING", "RESOLVED");
    private static final Set<String> VALIDATION_STATUSES = Set.of("VALID", "INVALID", "UNKNOWN", "UNCHECKED");

    SecretGuideContext {
        issuer = allowed(issuer, ISSUERS);
        credentialType = allowed(credentialType, TYPES);
        componentState = allowed(componentState, COMPONENT_STATES);
        stage = allowed(stage, STAGES);
        validationStatus = allowed(validationStatus, VALIDATION_STATUSES);
    }

    static SecretGuideContext of(String issuer, String credentialType, String componentState,
                                 String stage, String validationStatus) {
        return new SecretGuideContext(issuer, credentialType, componentState, stage,
                validationStatus);
    }

    Map<String, String> externalFields() {
        return Map.of("issuer", issuer, "credentialType", credentialType,
                "componentState", componentState, "stage", stage,
                "validationStatus", validationStatus);
    }

    boolean supportedIssuer() {
        return ISSUERS.contains(issuer);
    }

    private static String allowed(String value, Set<String> values) {
        return value != null && values.contains(value) ? value : "OTHER";
    }
}
