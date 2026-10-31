package com.logssey.secret.risk;

import com.logssey.secret.connection.SecretDisplayLabels;
import com.logssey.secret.risk.core.SecretRiskAssessmentStore;
import com.logssey.secret.risk.core.SecretRiskProvenance;
import com.logssey.secret.risk.core.SecretSeverityEngine;
import java.time.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;

/** Read-only explanation of existing evidence. Never probes a provider or changes a v2 result. */
final class SecretRiskAnalysisContext {
  private final JdbcTemplate jdbc;
  private final SecretRiskAssessmentStore store;
  private static final List<String> COVERAGE = List.of(
      "permissionCoverage", "targetCoverage", "restrictionCoverage", "classificationCoverage");
  private static final Set<String> CREDENTIAL_TYPES = Set.of(
      "AWS_ACCESS_KEY_PAIR", "AWS_TEMPORARY_CREDENTIALS", "AWS_ACCESS_KEY_ID",
      "GITHUB_CLASSIC_PAT", "GITHUB_FINE_GRAINED_PAT", "GITHUB_PAT", "NOTION_TOKEN");

  SecretRiskAnalysisContext(JdbcTemplate jdbc, SecretRiskAssessmentStore store) {
    this.jdbc = jdbc;
    this.store = store;
  }

  Map<String, Object> read(Map<String, Object> o, Map<String, Object> risk, OffsetDateTime now) {
    long occurrence = n(o, "occurrence_id");
    var policy = store.activePolicy();
    var current = store.snapshot(o, policy, now);
    var inputs = objectMap(current.get("inputs"));
    var ids = new HashSet<Long>();
    if (current.get("evidenceRefs") instanceof Collection<?> refs)
      refs.stream().filter(Number.class::isInstance).map(Number.class::cast)
          .forEach(id -> ids.add(id.longValue()));
    var accepted = new ArrayList<Map<String, Object>>();
    for (var row : jdbc.queryForList(
        "SELECT e.*,e.safe_payload::text AS payload FROM secret_current_risk_evidence e"
            + " WHERE e.occurrence_id=? ORDER BY e.observed_at DESC,e.evidence_id DESC", occurrence)) {
      if ("METADATA_ONLY".equals(o.get("component_state")) || !ids.contains(n(row, "evidence_id"))) continue;
      accepted.add(row);
    }
    var source = jdbc.queryForMap(
        "SELECT c.provider FROM secret_connections c WHERE c.connection_id=?", o.get("connection_id"));
    var result = new LinkedHashMap<String, Object>();
    result.put("occurrenceId", occurrence);
    result.put("evidenceRevision", o.get("risk_evidence_revision"));
    result.put("profileVersion", "risk-context-v1");
    result.put("readAt", now);
    result.put("source", Map.of("provider", code(source.get("provider"), "UNKNOWN"),
        "issuer", code(o.get("issuer"), "UNKNOWN"),
        "credentialType", CREDENTIAL_TYPES.contains(o.get("credential_type"))
            ? o.get("credential_type") : "UNKNOWN"));
    result.put("access", access(accepted, inputs));
    result.put("permissions", permissions(o, accepted,
        "METADATA_ONLY".equals(o.get("component_state")) ? Map.of() : current, inputs));
    result.put("asset", asset(o, accepted));
    var latest = objectMap(risk.get("latestAutomaticAssessment"));
    var explanation = new LinkedHashMap<String, Object>();
    String rule = Objects.toString(latest.get("ruleId"), "");
    explanation.put("ruleId", rule.matches("R0[0-7]|R99") ? rule : null);
    explanation.put("policyVersion", code(latest.get("policyVersion"),
        Objects.toString(policy.get("policy_version"), "severity-v2")));
    explanation.put("reasonCode", rule.matches("R0[0-7]|R99") ? "RULE_" + rule
        : "INITIAL_ASSESSMENT_REQUIRED");
    var explainedInputs = new TreeMap<String, Object>();
    objectMap(risk.get("inputs")).forEach((key, value) -> {
      if (SecretSeverityEngine.AXES.containsKey(key)
          && value instanceof String s && SecretSeverityEngine.AXES.get(key).contains(s))
        explainedInputs.put(key, value);
    });
    explanation.put("inputs", explainedInputs);
    var missing = new TreeSet<>(safeCodes(risk.get("missingReasonCodes")));
    missing.addAll(safeCodes(current.get("normalizerReasons")));
    explanation.put("missingReasonCodes", List.copyOf(missing));
    explanation.put("assessmentCurrent", Boolean.TRUE.equals(risk.get("currentEligible")));
    result.put("explanation", explanation);
    result.put("limitations", List.of("AUTOMATED_PERMISSION_ANALYSIS_UNSUPPORTED",
        "MANUAL_ASSET_LINK_NOT_PERMISSION_PROOF", "VALIDITY_NOT_PERMISSION_PROOF"));
    return result;
  }

  private Map<String, Object> access(List<Map<String, Object>> evidence, Map<String, Object> inputs) {
    String range = Objects.toString(inputs.get("exposureRange"), "UNKNOWN");
    var rows = evidence.stream().filter(r -> "ACCESS_SCOPE".equals(r.get("kind")))
        .filter(r -> supportsRange(range, store.map((String) r.get("payload"))))
        .toList();
    var result = common(rows);
    result.put("status", Set.of("BROAD", "BOUNDED").contains(range) ? "CONFIRMED" : "UNKNOWN");
    result.put("range", range);
    result.put("verificationLevel", rows.isEmpty() || "UNKNOWN".equals(range) ? null
        : rows.stream().allMatch(r -> "PROVIDER_OBSERVED".equals(r.get("verification_level")))
            ? "PROVIDER_OBSERVED" : "MANUAL_ACCEPTED");
    return result;
  }

  private boolean supportsRange(String range, Map<String, Object> facts) {
    if (!range.equals(facts.get("audienceClass"))) return false;
    return switch (range) {
      case "BROAD" -> Boolean.TRUE.equals(facts.get("publicAccessConfirmed"))
          || "COMPLETE".equals(facts.get("coverageStatus"));
      case "BOUNDED" -> "COMPLETE".equals(facts.get("coverageStatus"))
          && facts.get("boundedPrincipalCount") instanceof Number count && count.intValue() > 0;
      default -> true;
    };
  }

  private Map<String, Object> permissions(Map<String, Object> o, List<Map<String, Object>> evidence,
      Map<String, Object> snapshot, Map<String, Object> inputs) {
    var rows = evidence.stream().filter(r -> "PERMISSION_MAPPING".equals(r.get("kind"))).toList();
    var provenance = new SecretRiskProvenance(jdbc);
    var grounded = rows.stream().filter(r -> provenance.permissionGrounded(o,
        provenance.parse(r.get("source_refs"), store))).toList();
    var capabilities = safeCodes(snapshot.get("positiveCapabilities"));
    var targetScopes = new TreeSet<String>();
    var coverage = new TreeMap<String, Object>();
    for (String field : COVERAGE) {
      var values = new HashSet<String>();
      for (var row : grounded) values.add(Objects.toString(store.map((String) row.get("payload")).get(field), "UNKNOWN"));
      coverage.put(field, values.size() == 1 ? values.iterator().next()
          : values.isEmpty() ? "UNKNOWN" : "PARTIAL");
    }
    for (var row : grounded) {
      Object scope = store.map((String) row.get("payload")).get("targetScope");
      if (scope instanceof String s && Set.of("ASSET", "ACCOUNT", "ORGANIZATION").contains(s)) targetScopes.add(s);
    }
    boolean confirmed = !capabilities.isEmpty() && !"UNKNOWN".equals(inputs.get("impact"));
    var result = common(grounded);
    result.put("status", confirmed ? "CONFIRMED" : rows.isEmpty() ? "UNKNOWN" : "PARTIAL");
    result.put("capabilities", capabilities);
    result.put("verificationLevel", grounded.isEmpty() ? null : "MANUAL_ACCEPTED");
    result.put("mappingVersion", grounded.isEmpty() ? null : "manual-evidence-v1");
    result.put("targetScopes", targetScopes);
    result.put("coverage", coverage);
    result.put("reasonCodes", confirmed ? List.of()
        : grounded.isEmpty() && !rows.isEmpty() ? List.of("IDENTITY_BINDING_UNRESOLVED", "PERMISSION_MAPPING_INCOMPLETE")
        : safeCodes(snapshot.get("normalizerReasons")).stream()
            .filter(s -> s.contains("PERMISSION") || s.contains("IDENTITY") || s.contains("ASSET"))
            .toList());
    return result;
  }

  private Map<String, Object> asset(Map<String, Object> o, List<Map<String, Object>> evidence) {
    var result = new LinkedHashMap<String, Object>();
    result.put("status", "UNLINKED");
    result.put("assetId", null);
    result.put("label", null);
    result.put("provider", null);
    result.put("assetType", null);
    result.put("environment", "UNKNOWN");
    result.put("classification", null);
    result.put("evidenceIds", List.of());
    if (!(o.get("asset_id") instanceof Number id)) return result;
    var assets = jdbc.queryForList("SELECT asset_id,name,provider,asset_type,environment FROM assets WHERE asset_id=?", id.longValue());
    if (assets.isEmpty()) return result;
    var a = assets.getFirst();
    result.putAll(safeAsset(a));
    result.put("status", "LINKED");
    var provenance = new SecretRiskProvenance(jdbc);
    var classes = evidence.stream().filter(r -> "ASSET_CLASSIFICATION".equals(r.get("kind")))
        .filter(r -> {
          var facts = store.map((String) r.get("payload"));
          var refs = provenance.parse(r.get("source_refs"), store);
          return provenance.assetGrounded(o, refs, facts);
        }).toList();
    var distinct = new HashSet<Map<String, Object>>();
    for (var c : classes) {
      var facts = store.map((String) c.get("payload"));
      distinct.add(Map.of("sensitive", Boolean.TRUE.equals(facts.get("sensitive")),
          "important", Boolean.TRUE.equals(facts.get("important")), "testOnly", Boolean.TRUE.equals(facts.get("testOnly"))));
    }
    if (distinct.size() == 1) {
      result.put("status", "CLASSIFIED");
      result.put("classification", distinct.iterator().next());
      result.put("evidenceIds", classes.stream().map(r -> n(r, "evidence_id")).toList());
    }
    return result;
  }

  static Map<String, Object> safeAsset(Map<String, Object> row) {
    long id = n(row, "asset_id");
    String name = Objects.toString(row.get("name"), "");
    return Map.of("assetId", id, "label", SecretDisplayLabels.safeAlias(name) && !name.isBlank()
        ? name : "자산 #" + id, "provider", code(row.get("provider"), "UNKNOWN"),
        "assetType", SecretDisplayLabels.safeAlias(Objects.toString(row.get("asset_type"), ""))
            ? Objects.toString(row.get("asset_type"), "OTHER") : "OTHER",
        "environment", Set.of("PROD", "DEV", "TEST").contains(row.get("environment"))
            ? row.get("environment") : "UNKNOWN");
  }

  private Map<String, Object> common(List<Map<String, Object>> rows) {
    var result = new LinkedHashMap<String, Object>();
    result.put("observedAt", rows.isEmpty() ? null : SecretRiskAssessmentStore.time(rows.getFirst().get("observed_at")));
    OffsetDateTime until = null;
    for (var r : rows) {
      var expiry = SecretRiskAssessmentStore.time(r.get("expires_at"));
      var observed = SecretRiskAssessmentStore.time(r.get("observed_at"));
      var deadline = observed == null ? null : observed.plusHours("ACCESS_SCOPE".equals(r.get("kind")) ? 6 : 24);
      if (deadline != null && (expiry == null || deadline.isBefore(expiry))) expiry = deadline;
      if (expiry != null && (until == null || expiry.isBefore(until))) until = expiry;
    }
    result.put("validUntil", until);
    result.put("evidenceIds", rows.stream().map(r -> n(r, "evidence_id")).toList());
    return result;
  }

  private static long n(Map<String, Object> row, String key) { return ((Number) row.get(key)).longValue(); }
  private static String code(Object value, String fallback) {
    String s = Objects.toString(value, "");
    return s.matches("[A-Za-z][A-Za-z0-9_-]{0,79}") ? s : fallback;
  }
  private static Map<String, Object> objectMap(Object value) {
    var result = new LinkedHashMap<String, Object>();
    if (value instanceof Map<?, ?> map) map.forEach((k, v) -> result.put(k.toString(), v));
    return result;
  }
  private static List<String> safeCodes(Object value) {
    if (!(value instanceof Collection<?> values)) return List.of();
    return values.stream().filter(String.class::isInstance).map(String.class::cast)
        .filter(s -> s.matches("[A-Z][A-Z0-9_]{0,79}")).distinct().sorted().toList();
  }
}
