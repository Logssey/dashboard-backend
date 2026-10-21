package com.logssey.secret.query;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Combines only the occurrence IDs already selected by the caller's live ACL and filters. */
final class SecretRiskReadModel {
    private static final List<String> GRADES = List.of("LOW", "MEDIUM", "HIGH", "CRITICAL");

    private SecretRiskReadModel() {}

    static Map<String,Object> summarize(Collection<Long> occurrenceIds,
            Map<Long,Map<String,Object>> risks, boolean outsideAssessment) {
        String highest = null;
        long unassessed = 0, held = 0;
        boolean applicable = false;
        for (Long id : occurrenceIds.stream().distinct().toList()) {
            if (outsideAssessment) continue;
            Map<String,Object> risk = risks.getOrDefault(id, Map.of());
            var automatic = block(risk, "latestAutomaticAssessment");
            var effective = block(risk, "effectiveAssessment");
            String status = text(automatic.get("assessmentStatus"));
            if (status == null) status = text(risk.get("assessmentStatus"));
            if (!"NOT_APPLICABLE".equals(status)) applicable = true;
            if (status == null || "UNASSESSED".equals(status)) unassessed++;
            String grade = text(effective.get("severity"));
            if (grade == null) grade = text(risk.get("effectiveSeverity"));
            if (grade == null && "ASSESSED".equals(status)) grade = text(automatic.get("severity"));
            if (grade != null && GRADES.contains(grade)) {
                applicable = true;
                if (highest == null || GRADES.indexOf(grade) > GRADES.indexOf(highest)) highest = grade;
            }
            if (Boolean.TRUE.equals(effective.get("held"))) held++;
        }
        var result = new LinkedHashMap<String,Object>();
        String status = highest != null ? "ASSESSED" : applicable ? "UNASSESSED" : "NOT_APPLICABLE";
        result.put("assessmentStatus", status);
        result.put("severity", highest != null ? highest : "UNASSESSED".equals(status) ? "UNASSESSED" : null);
        result.put("effectiveSeverity", highest);
        result.put("unassessedOccurrenceCount", unassessed);
        result.put("heldOccurrenceCount", held);
        return result;
    }

    static void applyLocation(Map<String,Object> destination, Map<String,Object> risk, boolean metadata) {
        destination.putAll(summarize(List.of(1L), Map.of(1L, risk), metadata));
        for (String key : List.of("latestAutomaticAssessment", "effectiveAssessment", "lastConfirmedSeverity",
                "missingReasonCodes", "conflictReasonCodes", "freshness", "evidenceRevision")) {
            if (risk.containsKey(key)) destination.put(key, risk.get(key));
        }
    }

    static String revision(Map<String,Object> risk) {
        var automatic = block(risk, "latestAutomaticAssessment");
        var effective = block(risk, "effectiveAssessment");
        return String.valueOf(risk.get("evidenceRevision")) + ":" + automatic.get("assessmentId")
                + ":" + effective.get("assessmentId") + ":" + effective.get("held");
    }

    @SuppressWarnings("unchecked")
    private static Map<String,Object> block(Map<String,Object> value, String key) {
        return value.get(key) instanceof Map<?,?> nested ? (Map<String,Object>) nested : Map.of();
    }

    private static String text(Object value) { return value instanceof String s ? s : null; }
}
