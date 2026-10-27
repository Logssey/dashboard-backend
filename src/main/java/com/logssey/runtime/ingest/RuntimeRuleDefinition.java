package com.logssey.runtime.ingest;

public record RuntimeRuleDefinition(
        String ruleKey,
        String title,
        String version,
        String eventType,
        String targetType,
        ValidationProfile validationProfile) {

    public enum ValidationProfile {
        CONTAINER_SHELL,
        SERVICE_ACCOUNT_TOKEN_ACCESS,
        PACKAGE_MANAGER_EXECUTION,
        SENSITIVE_PATH_WRITE
    }
}
