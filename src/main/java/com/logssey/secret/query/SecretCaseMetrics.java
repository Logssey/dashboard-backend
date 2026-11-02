package com.logssey.secret.query;

import static com.logssey.secret.snapshot.SecretReadSnapshots.facts;

import java.time.OffsetDateTime;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Read projections only: no grade or provider result is written by aggregation. */
final class SecretCaseMetrics {
    static final List<String> SEVERITIES = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNASSESSED", "NOT_APPLICABLE");
    static final List<String> VALIDITIES = List.of("VALID", "INVALID", "UNKNOWN", "UNCHECKED");

    private SecretCaseMetrics() {}

    static String severity(Map<String, Object> item) {
        String grade = Objects.toString(item.get("severity"), "");
        if (SEVERITIES.contains(grade)) return grade;
        return "NOT_APPLICABLE".equals(item.get("assessmentStatus")) ? "NOT_APPLICABLE" : "UNASSESSED";
    }

    /**
     * The latest attempt in the visible case wins, including a failed attempt. A still-unchecked
     * material action at any unresolved location blocks reuse of another location's old success.
     * Six hours is the existing validation service's freshness window, not a new severity policy.
     */
    static Map<String, Object> validation(List<SecretLocationRepository.Row> rows, OffsetDateTime asOf) {
        var unresolved = rows.stream().filter(r -> !"RESOLVED".equals(r.actionStatus())).toList();
        var relevant = unresolved.isEmpty() ? rows : unresolved;
        if (relevant.stream().anyMatch(r -> "POST_ACTION_VALIDATION_REQUIRED".equals(r.validationReason()))) {
            return facts("validationStatus", "UNCHECKED", "validationFreshness", "POST_ACTION_REQUIRED",
                    "lastValidationStatus", null, "validationCheckedAt", null, "validationDueAt", null,
                    "validationReasonCode", "POST_ACTION_VALIDATION_REQUIRED");
        }
        var latest = relevant.stream().filter(r -> r.validationAttemptAt() != null)
                .max(Comparator.comparing(SecretLocationRepository.Row::validationAttemptAt)
                        .thenComparingLong(SecretLocationRepository.Row::occurrenceId)).orElse(null);
        if (latest == null) return facts("validationStatus", "UNCHECKED", "validationFreshness", "UNAVAILABLE",
                "lastValidationStatus", null, "validationCheckedAt", null, "validationDueAt", null,
                "validationReasonCode", "NO_VERIFICATION_ATTEMPT");
        String observed = latest.validity() != null && VALIDITIES.contains(latest.validity()) ? latest.validity() : "UNCHECKED";
        boolean conclusive = List.of("VALID", "INVALID").contains(observed);
        OffsetDateTime due = conclusive && latest.validationCheckedAt() != null ? latest.validationCheckedAt().plusHours(6) : null;
        boolean stale = due != null && !asOf.isBefore(due);
        String projected = stale || conclusive && due == null ? "UNKNOWN" : observed;
        String freshness = stale ? "STALE" : due != null ? "CURRENT" : "UNAVAILABLE";
        return facts("validationStatus", projected, "validationFreshness", freshness,
                "lastValidationStatus", observed, "validationCheckedAt", latest.validationCheckedAt(),
                "validationDueAt", due, "validationReasonCode", stale ? "CHECK_PERIOD_EXCEEDED" : latest.validationReason());
    }

    static Map<String, Object> matrix(List<Map<String, Object>> cases, boolean allowed,
            Map<String, String> filters, String snapshotId) {
        var cells = new java.util.ArrayList<Map<String, Object>>();
        boolean complete = cases.stream().allMatch(c -> c.get("validationStatus") instanceof String validity && VALIDITIES.contains(validity));
        boolean available = allowed && complete;
        if (available) for (String severity : SEVERITIES) for (String validity : VALIDITIES) {
            long count = cases.stream().filter(c -> severity.equals(severity(c))
                    && validity.equals(c.get("validationStatus"))).count();
            var queue = new LinkedHashMap<String, Object>(filters);
            queue.put("snapshotId", snapshotId); queue.put("bucket", "CURRENT_CASES");
            queue.put("severity", severity); queue.put("validity", validity);
            cells.add(facts("severity", severity, "validity", validity, "value", count, "queueFilter", queue));
        }
        return facts("scope", "currentCases", "unit", "ResponseCase", "status", !allowed ? "NOT_AUTHORIZED" : complete ? "AVAILABLE" : "LEGACY_UNAVAILABLE",
                "reasonCode", !allowed ? "ROLE_REQUIRED" : complete ? null : "LEGACY_SNAPSHOT_FACTS", "total", available ? cases.size() : null,
                "rows", SEVERITIES, "columns", VALIDITIES, "cells", cells,
                "staleValidationCaseCount", available ? cases.stream().filter(c -> "STALE".equals(c.get("validationFreshness"))).count() : null);
    }
}
