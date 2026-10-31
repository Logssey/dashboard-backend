package com.logssey.secret.run;

import java.time.OffsetDateTime;
import java.util.Map;

/** Independent units; unknown historical aggregates are null rather than fabricated zeros. */
public record SecretRunCoverageResponse(
        Long successfulScopeCount, long finishedScopeCount, Long gapScopeCount,
        long unverifiedScopeCount, Map<String, Long> scopeStatusCounts,
        String aggregationStatus, Long findingCount, Long distinctCredentialCount,
        Long newCredentialCount, String newCredentialCountReason, boolean coverageComplete,
        String unit, OffsetDateTime asOf, Revalidation revalidation, @com.fasterxml.jackson.annotation.JsonIgnore String provider, String safeDisplayAlias) {
    public record Revalidation(long caseId, long occurrenceId) { }
}
