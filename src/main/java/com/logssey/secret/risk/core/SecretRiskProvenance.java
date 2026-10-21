package com.logssey.secret.risk.core;

import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;

/** Validates real typed parents; a label or client confidence flag is never a parent. */
public final class SecretRiskProvenance {
  private final JdbcTemplate jdbc;

  public SecretRiskProvenance(JdbcTemplate jdbc) {
    this.jdbc = jdbc;
  }

  public record Ref(String type, long id, long version, String role) {}

  public void validate(Map<String, Object> occurrence, List<Ref> refs) {
    if (refs.size() > 30) throw new IllegalArgumentException("REFERENCE_LIMIT");
    for (Ref ref : refs) {
      if (ref == null
          || ref.type() == null
          || ref.role() == null
          || ref.id() <= 0
          || ref.version() < 0
          || !Set.of("ASSERTS", "BINDS_IDENTITY", "CLASSIFIES", "LIMITS").contains(ref.role())
          || !valid(occurrence, ref))
        throw new IllegalArgumentException("EVIDENCE_PARENT_UNAVAILABLE");
    }
  }

  public boolean valid(Map<String, Object> o, Ref ref) {
    long id = ((Number) o.get("occurrence_id")).longValue(),
        key = ((Number) o.get("credential_set_id")).longValue();
    return switch (ref.type()) {
      case "VALIDATION_ATTEMPT" ->
          ref.role().equals("BINDS_IDENTITY")
              && exists(
                  "SELECT EXISTS(SELECT 1 FROM secret_validation_attempts WHERE attempt_id=? AND"
                      + " occurrence_id=? AND credential_set_id=? AND credential_revision=? AND"
                      + " evidence_version=1 AND attempt_state='COMPLETED' AND result='VALID' AND"
                      + " provider_checked_at IS NOT NULL)",
                  ref.id(),
                  id,
                  key,
                  ref.version())
              && ref.version() == ((Number) o.get("credential_revision")).longValue();
      case "RISK_EVIDENCE" ->
          ref.role().equals("CLASSIFIES")
              && ref.version() == 1
              && exists(
                  "SELECT EXISTS(SELECT 1 FROM secret_current_risk_evidence WHERE evidence_id=? AND"
                      + " occurrence_id=? AND kind='ASSET_CLASSIFICATION' AND (expires_at IS NULL"
                      + " OR expires_at>clock_timestamp()))",
                  ref.id(),
                  id);
      case "ASSET" ->
          ref.role().equals("CLASSIFIES")
              && ref.version() == 1
              && o.get("asset_id") != null
              && ((Number) o.get("asset_id")).longValue() == ref.id()
              && exists("SELECT EXISTS(SELECT 1 FROM assets WHERE asset_id=?)", ref.id());
      case "INVESTIGATION_HISTORY" ->
          Set.of("ASSERTS", "LIMITS").contains(ref.role())
              && exists(
                  """
SELECT EXISTS(SELECT 1 FROM secret_investigation_history h JOIN secret_investigation_tasks t USING(task_id)
JOIN secret_investigation_history original ON original.history_id=(h.safe_changes->>'acceptedHistoryId')::bigint AND original.task_id=t.task_id
WHERE h.history_id=? AND h.task_version=? AND h.event_type='EVIDENCE_ACCEPTED'
AND original.event_type='EVIDENCE_ADDED' AND original.safe_changes->>'evidenceKind'='PROVIDER_REFERENCE'
AND t.target_type='OCCURRENCE' AND t.occurrence_id=? AND EXISTS(SELECT 1 FROM secret_role_grants g
  WHERE g.user_id=h.actor_user_id AND g.role='SECURITY' AND g.revoked_at IS NULL AND(g.connection_id IS NULL OR g.connection_id=?)))
""",
                  ref.id(),
                  ref.version(),
                  id,
                  o.get("connection_id"));
      default -> false;
    };
  }

  public boolean permissionGrounded(Map<String, Object> o, List<Ref> refs) {
    try {
      validate(o, refs);
    } catch (IllegalArgumentException invalid) {
      return false;
    }
    return refs.stream().anyMatch(r -> r.type().equals("VALIDATION_ATTEMPT"))
        && refs.stream().anyMatch(r -> r.type().equals("RISK_EVIDENCE"))
        && refs.stream()
            .anyMatch(r -> r.type().equals("INVESTIGATION_HISTORY") && r.role().equals("ASSERTS"))
        && refs.stream()
            .anyMatch(r -> r.type().equals("INVESTIGATION_HISTORY") && r.role().equals("LIMITS"));
  }

  public boolean assetGrounded(Map<String, Object> o, List<Ref> refs, Map<String, Object> facts) {
    return refs.stream()
        .filter(r -> r.type().equals("ASSET"))
        .anyMatch(
            r ->
                valid(o, r)
                    && Objects.equals(
                        facts.get("environment"),
                        jdbc.queryForObject(
                            "SELECT environment FROM assets WHERE asset_id=?",
                            String.class,
                            r.id())));
  }

  public List<Ref> parse(Object value, SecretRiskAssessmentStore store) {
    if (value == null) return List.of();
    var rows = store.json.readValue(value.toString(), List.class);
    var refs = new ArrayList<Ref>();
    for (Object item : rows) {
      if (!(item instanceof Map<?, ?> m)
          || !m.keySet().equals(Set.of("type", "id", "version", "role"))
          || !(m.get("id") instanceof Number id)
          || !(m.get("version") instanceof Number version))
        throw new IllegalArgumentException("INVALID_REFERENCE");
      refs.add(
          new Ref(
              (String) m.get("type"), id.longValue(), version.longValue(), (String) m.get("role")));
    }
    return refs;
  }

  public List<Map<String, Object>> available(Map<String, Object> o) {
    var result = new ArrayList<Map<String, Object>>();
    long occurrence = ((Number) o.get("occurrence_id")).longValue();
    for (var r :
        jdbc.queryForList(
            "SELECT attempt_id,credential_revision,provider_checked_at FROM"
                + " secret_validation_attempts WHERE occurrence_id=? AND credential_set_id=? AND"
                + " credential_revision=? AND evidence_version=1 AND attempt_state='COMPLETED' AND"
                + " result='VALID' AND provider_checked_at IS NOT NULL ORDER BY attempt_id DESC"
                + " LIMIT 20",
            occurrence,
            o.get("credential_set_id"),
            o.get("credential_revision")))
      result.add(
          option(
              "VALIDATION_ATTEMPT",
              ((Number) r.get("attempt_id")).longValue(),
              ((Number) r.get("credential_revision")).longValue(),
              "BINDS_IDENTITY",
              "ACTUAL_IDENTITY_OBSERVATION",
              r.get("provider_checked_at")));
    for (var r :
        jdbc.queryForList(
            "SELECT evidence_id,observed_at FROM secret_current_risk_evidence WHERE occurrence_id=?"
                + " AND kind='ASSET_CLASSIFICATION' AND expires_at>clock_timestamp() ORDER BY"
                + " evidence_id DESC LIMIT 20",
            occurrence))
      result.add(
          option(
              "RISK_EVIDENCE",
              ((Number) r.get("evidence_id")).longValue(),
              1,
              "CLASSIFIES",
              "ASSET_CLASSIFICATION",
              r.get("observed_at")));
    for (var r :
        jdbc.queryForList(
            "SELECT h.history_id,h.task_version,h.created_at FROM secret_investigation_history h"
                + " JOIN secret_investigation_tasks t USING(task_id) WHERE"
                + " t.target_type='OCCURRENCE' AND t.occurrence_id=? AND"
                + " h.event_type='EVIDENCE_ACCEPTED' ORDER BY h.history_id DESC LIMIT 20",
            occurrence))
      for (String role : List.of("ASSERTS", "LIMITS")) {
        var ref =
            new Ref(
                "INVESTIGATION_HISTORY",
                ((Number) r.get("history_id")).longValue(),
                ((Number) r.get("task_version")).longValue(),
                role);
        if (valid(o, ref))
          result.add(
              option(
                  ref.type(),
                  ref.id(),
                  ref.version(),
                  role,
                  "ACCEPTED_PROVIDER_REFERENCE",
                  r.get("created_at")));
      }
    if (o.get("asset_id") != null)
      result.add(
          option(
              "ASSET",
              ((Number) o.get("asset_id")).longValue(),
              1,
              "CLASSIFIES",
              "REGISTERED_ASSET",
              null));
    return result;
  }

  private Map<String, Object> option(
      String type, long id, long version, String role, String label, Object at) {
    var result = new LinkedHashMap<String, Object>();
    result.put("type", type);
    result.put("id", id);
    result.put("version", version);
    result.put("role", role);
    result.put("labelCode", label);
    result.put("observedAt", SecretRiskAssessmentStore.time(at));
    return result;
  }

  private boolean exists(String sql, Object... args) {
    return Boolean.TRUE.equals(jdbc.queryForObject(sql, Boolean.class, args));
  }
}
