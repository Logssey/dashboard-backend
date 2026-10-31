package com.logssey.runtime.ingest;

import java.util.Optional;

public record RuntimeNormalizationResult(NormalizedRuntimeEvent event, String ignoredReason) {

    public RuntimeNormalizationResult {
        if ((event == null) == (ignoredReason == null)) {
            throw new IllegalArgumentException("Exactly one of event or ignoredReason must be present");
        }
    }

    public static RuntimeNormalizationResult normalized(NormalizedRuntimeEvent event) {
        return new RuntimeNormalizationResult(event, null);
    }

    public static RuntimeNormalizationResult ignored(String reason) {
        return new RuntimeNormalizationResult(null, reason);
    }

    public Optional<NormalizedRuntimeEvent> normalizedEvent() {
        return Optional.ofNullable(event);
    }
}
