package com.logssey.runtime.ingest;

import java.util.List;
import java.util.Map;

public record RuntimeRuleDefinition(
        String ruleKey,
        String title,
        String version,
        String eventType,
        String targetType,
        String operation,
        Mode mode,
        Maturity maturity,
        ValidationProfile validationProfile,
        List<String> sensors,
        List<String> mitreTechniques,
        int noiseBudgetPerMinute,
        String owner,
        Map<String, List<String>> sourceRules) {

    public RuntimeRuleDefinition {
        sensors = List.copyOf(sensors);
        mitreTechniques = List.copyOf(mitreTechniques);
        sourceRules = sourceRules.entrySet().stream().collect(java.util.stream.Collectors.toUnmodifiableMap(
                Map.Entry::getKey,
                entry -> List.copyOf(entry.getValue())));
    }

    public enum Mode {
        DETECT,
        OBSERVE,
        DRAFT
    }

    public enum Maturity {
        STABLE,
        INCUBATING,
        EXPERIMENTAL
    }

    public enum ValidationProfile {
        CONTAINER_SHELL,
        SERVICE_PROCESS_SHELL,
        SERVICE_ACCOUNT_TOKEN_ACCESS,
        PACKAGE_MANAGER_EXECUTION,
        NETWORK_EVENT,
        PROCESS_MEMORY_ACCESS,
        SENSITIVE_PATH_WRITE,
        CONTAINER_LIFECYCLE_EVENT,
        GENERIC_CONTAINER_PROCESS,
        GENERIC_CONTAINER_FILE,
        TEMP_EXECUTION,
        DOWNLOADER_EXECUTION,
        IDENTITY_FILE_CHANGE,
        PERSISTENCE_FILE_CHANGE,
        SSH_AUTHORIZED_KEYS_CHANGE,
        PRIVILEGE_CHANGE
    }
}
