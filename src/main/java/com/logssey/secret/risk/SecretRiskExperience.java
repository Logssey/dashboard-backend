package com.logssey.secret.risk;

import com.logssey.secret.risk.core.SecretRiskAssessmentStore;
import com.logssey.secret.access.*;
import com.logssey.secret.risk.permission.SecretPermissionObservationEligibility;
import com.logssey.secret.permission.core.SecretPermissionContext;
import java.time.OffsetDateTime;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;

/** Safe, additive read projection. No provider call, state transition or AI inference. */
final class SecretRiskExperience {
  private static final List<String> AXES = List.of("exposure", "exposureRange", "credential", "impact", "abuse", "validity");
  private static final List<String> LABELS = List.of("보관·공유 적정성", "접근 가능 범위", "키 구성 확인", "권한과 자원 영향", "중대한 사고 근거", "현재 인증 상태");
  private static final List<String> ACTIONS = List.of("REVIEW_STORAGE_POLICY", "REVIEW_ACCESS", "COMPLETE_CREDENTIAL", "REVIEW_PERMISSIONS", "REVIEW_INCIDENT_EVIDENCE", "REQUEST_VALIDATION");
  private final JdbcTemplate jdbc;
  private final SecretRiskAssessmentStore store;
  SecretRiskExperience(JdbcTemplate jdbc, SecretRiskAssessmentStore store) { this.jdbc = jdbc; this.store = store; }

  Map<String, Object> read(SecretPrincipal actor, Map<String, Object> o, Map<String, Object> risk,
      Map<String, Object> context, Map<String, Object> validation, OffsetDateTime now) {
    boolean metadata = "METADATA_ONLY".equals(o.get("component_state"));
    boolean eligible = Boolean.TRUE.equals(risk.get("currentEligible"));
    var inputs = object(context.get("currentInputs"));
    var authFreshness = object(validation.get("freshness"));
    var authLatest = object(validation.get("latestAttempt"));
    String authentication = "CURRENT".equals(authFreshness.get("status"))
        ? Objects.toString(authLatest.get("result"), "UNKNOWN")
        : authLatest.isEmpty() ? "UNCHECKED" : "UNKNOWN";
    inputs.put("validity", authentication);
    var latest = object(risk.get("latestAutomaticAssessment"));
    var effective = object(risk.get("effectiveAssessment"));
    var currentReasons = codes(context.get("currentReasonCodes"));
    boolean conflict = currentReasons.stream().anyMatch(Set.of("ACCESS_POLICY_CONFLICT", "EXPOSURE_INCIDENT_CONFLICT")::contains);
    String summaryStatus = metadata ? "METADATA_ONLY" : latest.get("assessmentId") == null ? "UNASSESSED"
        : !eligible ? "STALE" : Boolean.TRUE.equals(risk.get("unassessed")) ? "UNASSESSED" : "CURRENT";
    String rule = Objects.toString(latest.get("ruleId"), "");
    String summaryReason = metadata ? "METADATA_ONLY" : latest.get("assessmentId") == null ? "INITIAL_ASSESSMENT_REQUIRED"
        : !eligible ? "STALE_EVIDENCE" : rule.matches("R0[0-7]|R99") ? "RULE_" + rule : "INITIAL_ASSESSMENT_REQUIRED";
    var summary = new LinkedHashMap<String, Object>();
    summary.put("status", summaryStatus); summary.put("reasonCode", summaryReason);
    summary.put("ruleId", latest.get("ruleId"));
    summary.put("severity", effective.get("severity"));
    summary.put("automaticSeverity", latest.get("severity"));
    summary.put("held", Boolean.TRUE.equals(effective.get("held")));
    var criteria = new ArrayList<Map<String, Object>>();
    var missing = new ArrayList<Map<String, Object>>();
    boolean allowed = "NORMAL".equals(inputs.get("exposure")) && !conflict;
    for (int index = 0; index < AXES.size(); index++) {
      String axis = AXES.get(index), value = Objects.toString(inputs.get(axis), "UNKNOWN");
      boolean unknown = Set.of("UNKNOWN", "UNCHECKED", "CANDIDATE", "NOT_CONFIRMED").contains(value);
      boolean required = !metadata && !allowed && !axis.equals("abuse") && unknown;
      String evidenceType = switch (axis) { case "exposureRange" -> "ACCESS_SCOPE";
        case "impact" -> "PERMISSION_MAPPING"; case "abuse" -> "ABUSE_LINK"; default -> null; };
      var relevantReasons = new ArrayList<String>();
      for (String code : currentReasons)
        if ((axis.equals("exposure") && (code.contains("EXPOSURE") || code.equals("ACCESS_POLICY_CONFLICT")))
            || (unknown && axis.equals("exposureRange") && (code.contains("ACCESS") || code.contains("SOURCE_REVISION")))
            || (unknown && axis.equals("impact") && (code.contains("PERMISSION") || code.contains("IDENTITY") || code.contains("ASSET")))
            || (axis.equals("abuse") && code.contains("INCIDENT"))) relevantReasons.add(code);
      if (unknown && context.get("excludedEvidence") instanceof List<?> exclusions)
        for (Object excluded : exclusions) {
          var item = object(excluded);
          if (Objects.equals(evidenceType, item.get("kind"))
              || axis.equals("impact") && "ASSET_CLASSIFICATION".equals(item.get("kind"))) {
            Object code = item.get("reasonCode");
            if (code instanceof String s && !relevantReasons.contains(s)) relevantReasons.add(s);
          }
        }
      String status = "CANDIDATE".equals(value) ? "CANDIDATE" : unknown ? "UNKNOWN" : "CONFIRMED";
      if (axis.equals("validity")) {
        relevantReasons.clear(); relevantReasons.addAll(codes(authFreshness.get("reasonCodes")));
        if (Set.of("STALE", "POST_ACTION_REQUIRED").contains(Objects.toString(authFreshness.get("status"), ""))) status = "STALE";
      }
      if (relevantReasons.stream().anyMatch(s -> s.contains("CONFLICT"))) status = "CONFLICT";
      else if (unknown && relevantReasons.contains("STALE_EVIDENCE")) status = "STALE";
      var row = new LinkedHashMap<String, Object>();
      row.put("axis", axis); row.put("label", LABELS.get(index)); row.put("value", value); row.put("status", status);
      row.put("reasonCodes", relevantReasons);
      row.put("evidenceIds", evidenceIds(context, axis));
      row.put("nextAction", metadata || !required ? "NONE" : ACTIONS.get(index));
      criteria.add(row);
      if (required) missing.add(fact(axis.toUpperCase(Locale.ROOT) + "_REQUIRED", evidenceType, ACTIONS.get(index)));
    }
    if (!metadata)
      for (var criterion : criteria) if (Set.of("UNKNOWN", "STALE", "CONFLICT").contains(criterion.get("status"))
          && !Set.of("abuse", "validity").contains(criterion.get("axis"))
          && (!allowed || Set.of("exposure", "exposureRange").contains(criterion.get("axis"))))
        for (String code : codes(criterion.get("reasonCodes"))) {
          String evidenceType = switch (criterion.get("axis").toString()) { case "exposureRange" -> "ACCESS_SCOPE";
            case "impact" -> "PERMISSION_MAPPING"; default -> null; };
          String action = code.contains("CONFLICT") ? "INVESTIGATE_CONFLICT"
              : evidenceType == null ? "REVIEW_STORAGE_POLICY" : evidenceType.equals("ACCESS_SCOPE") ? "REVIEW_ACCESS" : "REVIEW_PERMISSIONS";
          var fact = fact(code, evidenceType, action); if (!missing.contains(fact)) missing.add(fact);
        }
    if (!metadata && latest.get("assessmentId") == null) missing.add(fact("INITIAL_ASSESSMENT_REQUIRED", null, "REQUEST_ASSESSMENT"));
    else if (!metadata && !eligible) missing.add(fact("ASSESSMENT_REFRESH_REQUIRED", null, "REQUEST_ASSESSMENT"));
    String source = Objects.toString(object(context.get("source")).get("provider"), "UNKNOWN");
    String issuer = Objects.toString(o.get("issuer"), "UNKNOWN"), type = Objects.toString(o.get("credential_type"), "UNKNOWN");
    boolean permissionType = Set.of("AWS_ACCESS_KEY_PAIR", "AWS_TEMPORARY_CREDENTIALS", "GITHUB_CLASSIC_PAT", "GITHUB_FINE_GRAINED_PAT").contains(type);
    boolean supported = permissionType && (!issuer.equals("GITHUB") || source.equals("GITHUB"));
    String permissionReason = !permissionType ? "UNSUPPORTED_TYPE" : !supported ? "CROSS_SOURCE_PERMISSION_UNSUPPORTED" : "HUMAN_CONFIRMATION_REQUIRED";
    var permittedCandidates = permissionCandidates(actor, o, now);
    boolean candidate = permittedCandidates.stream().anyMatch(row -> importantCapabilities(store.map(row.get("facts").toString())));
    var cases = jdbc.queryForList("SELECT c.action_status FROM secret_case_occurrences co JOIN secret_response_cases c USING(case_id)"
        + " WHERE co.occurrence_id=? AND c.is_current ORDER BY c.case_id DESC LIMIT 1", o.get("occurrence_id"));
    boolean unresolved = cases.isEmpty() || !"RESOLVED".equals(cases.getFirst().get("action_status"));
    String grade = Objects.toString(effective.get("severity"), Objects.toString(latest.get("severity"), ""));
    var priority = SecretWorkPriority.describe(grade, Boolean.TRUE.equals(risk.get("unassessed")),
        metadata || (allowed && !conflict), unresolved,
        !metadata && "PRESENT".equals(o.get("presence_status")) && publicOriginal(context),
        "VALID".equals(inputs.get("validity")), candidate,
        null, now);
    String level = priority.get("level").toString();
    OffsetDateTime basis = null;
    String basisKind = "UNCONFIRMED";
    if (Set.of("LOW", "MEDIUM", "HIGH", "CRITICAL").contains(grade)) {
      basis = gradeSignalAt(o, grade);
      if (basis != null) basisKind = "GRADE_ACTIVATED";
    } else if ("GENERAL".equals(level)) {
      basis = SecretRiskAssessmentStore.time(o.get("first_seen_at"));
      if (basis != null) basisKind = "FIRST_OBSERVED";
    }
    if ("PRIORITY".equals(level) && basis == null) {
      basis = new SecretPrioritySignalBasis(jdbc).firstObserved(o, now, permittedCandidates);
      if (basis != null) basisKind = "PRIORITY_SIGNAL_OBSERVED";
    }
    if ("INVENTORY".equals(level)) { basis = null; basisKind = "NOT_APPLICABLE"; }
    priority.put("targetBasis", basisKind); priority.put("targetBasisAt", basis);
    int ackHours = switch (level) { case "IMMEDIATE" -> 1; case "PRIORITY" -> 4; case "GENERAL" -> 9; case "PLANNED" -> 27; default -> 0; };
    int planHours = switch (level) { case "IMMEDIATE" -> 4; case "PRIORITY" -> 24; default -> 0; };
    priority.put("acknowledgeDueAt", basis == null || ackHours == 0 ? null : SecretWorkPriority.plusBusinessHours(basis, ackHours));
    priority.put("planDueAt", basis == null || planHours == 0 ? null : SecretWorkPriority.plusBusinessHours(basis, planHours));
    var result = new LinkedHashMap<String, Object>();
    result.put("version", "risk-experience-v1"); result.put("readAt", now);
    result.put("severityLabel", "시크릿 노출 심각도"); result.put("summary", summary);
    result.put("sourcePresenceObservedAt", SecretRiskAssessmentStore.time(o.get("last_seen_at")));
    result.put("authentication", Map.of("currentResult", authentication, "freshness", authFreshness,
        "latestAttempt", authLatest, "lastConclusiveValidation", object(validation.get("lastConclusiveValidation"))));
    result.put("criteria", criteria); result.put("missingFacts", missing); result.put("workPriority", priority);
    result.put("riskAcceptance", Map.of("enabled", false, "reasonCode", "RISK_ACCEPTANCE_DISABLED",
        "allowedSeverities", List.of("MEDIUM", "LOW"), "maximumDays", 7));
    result.put("support", Map.of("permissionAssistance", Map.of("status", supported ? "PARTIAL" : "UNSUPPORTED",
        "reasonCodes", List.of(permissionReason)), "automaticUsage", Map.of("status", "UNSUPPORTED",
        "reasonCodes", List.of("USAGE_HISTORY_NOT_AVAILABLE"))));
    return result;
  }

  private List<Map<String, Object>> permissionCandidates(SecretPrincipal actor, Map<String, Object> o, OffsetDateTime now) {
    var context = new SecretPermissionContext(jdbc).read(((Number) o.get("occurrence_id")).longValue());
    var result = new ArrayList<Map<String, Object>>();
    for (var row : jdbc.queryForList("SELECT p.*,p.safe_facts::text AS facts,r.context_version,r.identity_id,r.collector_connection_id,r.baseline::text AS baseline FROM secret_permission_observations p"
        + " JOIN secret_permission_requests r USING(request_id) WHERE r.occurrence_id=? AND p.expires_at>?"
        + " AND p.status<>'UNSUPPORTED' AND NOT EXISTS(SELECT 1 FROM secret_permission_decisions d WHERE d.observation_id=p.observation_id AND d.decision='REJECTED')",
        o.get("occurrence_id"), now)) {
      if (!SecretPermissionObservationEligibility.current(jdbc, new SecretAccessService(jdbc), actor, context, row, now)) continue;
      if (importantCapabilities(store.map(row.get("facts").toString()))) result.add(row);
    }
    return result;
  }
  private static boolean importantCapabilities(Map<String, Object> facts) {
    return codes(facts.get("capabilities")).stream().anyMatch(Set.of("IDENTITY_ADMINISTRATION", "SECURITY_SETTINGS_WRITE",
        "RESOURCE_ADMINISTRATION", "PRODUCTION_DEPLOY", "SENSITIVE_DATA_READ")::contains);
  }

  private boolean publicOriginal(Map<String, Object> context) {
    return Boolean.TRUE.equals(object(context.get("access")).get("repositoryPublicObserved"))
        || "CONFIRMED".equals(object(context.get("access")).get("status"))
            && Boolean.TRUE.equals(object(context.get("access")).get("publicAccessConfirmed"));
  }
  private OffsetDateTime gradeSignalAt(Map<String, Object> occurrence, String grade) {
    return jdbc.queryForObject("""
SELECT min(a.created_at) FROM secret_severity_assessments a
JOIN secret_severity_assessments target ON target.assessment_id=a.target_assessment_id
WHERE a.occurrence_id=? AND a.record_kind='APPLICATION' AND a.decision='APPLY' AND target.severity=?
AND a.occurrence_sequence>COALESCE((SELECT max(previous.occurrence_sequence)
 FROM secret_severity_assessments previous JOIN secret_severity_assessments prior ON prior.assessment_id=previous.target_assessment_id
 WHERE previous.occurrence_id=a.occurrence_id AND previous.record_kind='APPLICATION' AND previous.decision='APPLY'
 AND prior.severity IS DISTINCT FROM ?),0)
""", OffsetDateTime.class, occurrence.get("occurrence_id"), grade, grade);
  }
  private static List<?> evidenceIds(Map<String, Object> context, String axis) {
    String name = switch (axis) { case "exposureRange" -> "access"; case "impact" -> "permissions"; default -> ""; };
    Object ids = object(context.get(name)).get("evidenceIds"); return ids instanceof List<?> list ? list : List.of();
  }
  private static Map<String, Object> fact(String code, String evidenceType, String action) {
    var result = new LinkedHashMap<String, Object>(); result.put("code", code);
    result.put("evidenceType", evidenceType); result.put("action", action); return result;
  }
  private static Map<String, Object> object(Object value) {
    var result = new LinkedHashMap<String, Object>();
    if (value instanceof Map<?, ?> map) map.forEach((key, item) -> result.put(key.toString(), item)); return result;
  }
  private static List<String> codes(Object value) {
    return value instanceof Collection<?> collection ? collection.stream().filter(String.class::isInstance)
        .map(String.class::cast).filter(s -> s.matches("[A-Z][A-Z0-9_]{0,79}")).toList() : List.of();
  }
}
