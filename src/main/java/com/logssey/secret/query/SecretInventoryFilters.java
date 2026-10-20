package com.logssey.secret.query;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

public record SecretInventoryFilters(String origin, String source, String provider, String environment,
        String contentKind, String workBucket, String componentState, String validity, String severity) {
    public SecretInventoryFilters {
        require(origin, "PRODUCTION", "TEST", "UNCLASSIFIED");
        require(source, "ALL", "GITHUB", "AWS", "NOTION", "KUBERNETES");
        require(provider, "ALL", "GITHUB", "AWS", "NOTION", "KUBERNETES");
        require(environment, "ALL", "PROD", "DEV", "UNKNOWN");
        require(contentKind, "ALL", "VALUE_FINDINGS", "METADATA");
        require(workBucket, "ALL", "NEEDS_DECISION", "ACTION_REQUIRED", "NORMAL_INVENTORY", "NEEDS_CASE_LINK");
        require(componentState, "ALL", "CONFIRMED", "CANDIDATE", "METADATA_ONLY");
        require(validity, "ALL", "VALID", "INVALID", "UNKNOWN", "UNCHECKED");
        require(severity, "ALL", "UNASSESSED", "LOW", "MEDIUM", "HIGH", "CRITICAL");
    }
    public Map<String, String> normalized() {
        var map = new LinkedHashMap<String, String>();
        map.put("origin", origin); map.put("source", source); map.put("provider", provider);
        map.put("environment", environment); map.put("contentKind", contentKind); map.put("workBucket", workBucket);
        map.put("componentState", componentState); map.put("validity", validity); map.put("severity", severity);
        return map;
    }
    public static void require(String value, String... allowed) {
        if (value == null || !Set.of(allowed).contains(value)) throw new ApiException(ErrorCode.INVALID_INPUT);
    }
}
