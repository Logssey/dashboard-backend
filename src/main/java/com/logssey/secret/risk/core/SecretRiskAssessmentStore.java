package com.logssey.secret.risk.core;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.json.JsonMapper;

/** Shared API/worker DB logic; callers hold the location lock and a transaction. */
public final class SecretRiskAssessmentStore {
  public final JdbcTemplate jdbc;
  public final JsonMapper json = JsonMapper.builder().findAndAddModules().build();

  public SecretRiskAssessmentStore(JdbcTemplate jdbc) {
    this.jdbc = jdbc;
  }

  public Map<String, Object> location(long id, boolean lock) {
    return jdbc.queryForMap(
        """
SELECT o.*,k.component_state,k.credential_revision,k.issuer,k.credential_type,s.revision AS scope_revision,s.response_origin_version
FROM secret_occurrences o JOIN secret_credential_sets k USING(credential_set_id) JOIN secret_connection_scopes s USING(scope_id)
WHERE o.occurrence_id=?
"""
            + (lock ? " FOR UPDATE OF o" : ""),
        id);
  }

  public Map<String, Object> activePolicy() {
    return jdbc.queryForMap("SELECT * FROM secret_severity_policies WHERE state='ACTIVE'");
  }

  public List<SecretSeverityEngine.Rule> rules(long policy) {
    return jdbc.query(
        "SELECT rule_id,ordinal,conditions::text,result_status,result_severity FROM"
            + " secret_severity_rules WHERE policy_id=? ORDER BY ordinal",
        (r, n) ->
            new SecretSeverityEngine.Rule(
                r.getString(1), r.getInt(2), map(r.getString(3)), r.getString(4), r.getString(5)),
        policy);
  }

  public Map<String, Object> snapshot(
      Map<String, Object> o, Map<String, Object> policy, OffsetDateTime asOf) {
    var freshness = map(policy.get("freshness_profile").toString());
    var mappingManifest = map(policy.get("permission_mapping_manifest").toString());
    long id = number(o, "occurrence_id");
    var input = new TreeMap<String, String>();
    var reasons = new TreeSet<String>();
    var heads = new TreeMap<String, Object>();
    var refs = new ArrayList<Long>();
    var excluded = new ArrayList<Map<String, Object>>();
    OffsetDateTime evidenceValidUntil = null;
    var exposure =
        jdbc.queryForList(
            "SELECT assessment_id,decision,scope_revision,scope_origin FROM"
                + " secret_exposure_assessments WHERE occurrence_id=? ORDER BY version DESC LIMIT"
                + " 1",
            id);
    String status = "UNKNOWN";
    if (!exposure.isEmpty()) {
      var e = exposure.getFirst();
      heads.put("exposureDecision", number(e, "assessment_id"));
      if (Set.of("NORMAL", "ABNORMAL").contains(e.get("decision"))
          && e.get("scope_revision") != null
          && number(e, "scope_revision") == number(o, "scope_revision")
          && !Boolean.TRUE.equals(o.get("policy_recheck_required")))
        status = (String) e.get("decision");
    }
    if ("NORMAL".equals(status)) {
      boolean allowed =
          Boolean.TRUE.equals(
              jdbc.queryForObject(
                  "SELECT policy_result='ALLOWED' AND NOT requires_reassessment FROM"
                      + " secret_occurrence_policy_results WHERE occurrence_id=?",
                  Boolean.class,
                  id));
      if (!allowed) {
        status = "UNKNOWN";
        reasons.add("NORMAL_POLICY_EVIDENCE_STALE");
      }
    }
    input.put("exposure", status);
    input.put("exposureRange", "UNKNOWN");
    input.put(
        "credential", "CONFIRMED".equals(o.get("component_state")) ? "CONFIRMED" : "CANDIDATE");
    input.put("impact", "UNKNOWN");
    input.put("abuse", "NOT_CONFIRMED");
    input.put("validity", "UNCHECKED");
    var validation =
        jdbc.queryForList(
            "SELECT attempt_id,result FROM secret_current_validation_attempts WHERE"
                + " credential_set_id=? AND occurrence_id=? ORDER BY completed_at DESC,attempt_id"
                + " DESC LIMIT 1",
            number(o, "credential_set_id"),
            id);
    if (!validation.isEmpty()) {
      heads.put("validationAttempt", number(validation.getFirst(), "attempt_id"));
      input.put("validity", (String) validation.getFirst().get("result"));
    }
    var evidence =
        jdbc.queryForList(
            """
SELECT e.*,e.safe_payload::text AS payload FROM secret_current_risk_evidence e WHERE e.occurrence_id=?
AND NOT(e.kind='ACCESS_SCOPE' AND e.source_kind='PROVIDER_OBSERVATION' AND EXISTS(
 SELECT 1 FROM secret_current_risk_evidence newer WHERE newer.occurrence_id=e.occurrence_id
 AND newer.kind=e.kind AND newer.source_kind=e.source_kind AND newer.writer_service_id=e.writer_service_id
 AND newer.collector_connection_id=e.collector_connection_id AND newer.credential_revision=e.credential_revision
 AND newer.scope_revision=e.scope_revision AND newer.source_object_version IS NOT DISTINCT FROM e.source_object_version
 AND (newer.observed_at,newer.evidence_id)>(e.observed_at,e.evidence_id)))
ORDER BY CASE e.kind WHEN 'ASSET_CLASSIFICATION' THEN 0 ELSE 1 END,e.evidence_id
""",
            id);
    heads.put(
        "evidenceHead",
        jdbc.queryForObject(
            "SELECT COALESCE(max(evidence_id),0) FROM secret_risk_evidence WHERE occurrence_id=?",
            Long.class,
            id));
    heads.put("objectVersion", Objects.toString(o.get("latest_object_version"), ""));
    heads.put("lastSeenRun", Objects.toString(o.get("last_seen_run_id"), ""));
    heads.put("scopeRevision", number(o, "scope_revision"));
    heads.put("originRevision", number(o, "response_origin_version"));
    heads.put("credentialRevision", number(o, "credential_revision"));
    heads.put("policyBinding", Objects.toString(o.get("policy_assessed_binding_id"), ""));
    var ranges = new HashSet<String>();
    var impacts = new HashSet<String>();
    var abuse = new HashSet<Boolean>();
    boolean classificationPresent = false;
    boolean minimalAssets = true;
    boolean importantAssets = false;
    boolean sensitiveAssets = false;
    boolean permissionIncomplete = false;
    var positiveCapabilities = new TreeSet<String>();
    var provenance = new SecretRiskProvenance(jdbc);
    for (var e : evidence) {
      String kind = (String) e.get("kind");
      OffsetDateTime observed = time(e.get("observed_at"));
      OffsetDateTime expiry = time(e.get("expires_at"));
      if (number(e, "credential_revision") != number(o, "credential_revision")
          || number(e, "scope_revision") != number(o, "scope_revision")) {
        reasons.add("STALE_EVIDENCE");
        excluded.add(excluded(e, "STALE_EVIDENCE"));
        continue;
      }
      if (!kind.equals("ABUSE_LINK")
          && (!Objects.equals(e.get("source_object_version"), o.get("latest_object_version"))
              || expiry == null
              || !asOf.isBefore(expiry))) {
        reasons.add("STALE_EVIDENCE");
        excluded.add(excluded(e, "STALE_EVIDENCE"));
        continue;
      }
      long max =
          ((Number)
                  freshness.get(
                      kind.equals("ACCESS_SCOPE")
                          ? "accessMaxSeconds"
                          : kind.equals("ASSET_CLASSIFICATION")
                              ? "assetMaxSeconds"
                              : "permissionMaxSeconds"))
              .longValue();
      if (observed.isAfter(
          asOf.plusSeconds(((Number) freshness.get("futureSkewSeconds")).longValue()))) {
        reasons.add("TIME_UNCERTAIN");
        excluded.add(excluded(e, "TIME_UNCERTAIN"));
        continue;
      }
      if (!kind.equals("ABUSE_LINK") && !asOf.isBefore(observed.plusSeconds(max))) {
        reasons.add("STALE_EVIDENCE");
        excluded.add(excluded(e, "STALE_EVIDENCE"));
        continue;
      }
      String applicabilityProblem = SecretRiskApplicability.rejection(e, o, asOf);
      if (applicabilityProblem != null) {
        reasons.add(applicabilityProblem);
        excluded.add(excluded(e, applicabilityProblem));
        continue;
      }
      var facts = map((String) e.get("payload"));
      var sourceRefs = provenance.parse(e.get("source_refs"), this);
      refs.add(number(e, "evidence_id"));
      if (!kind.equals("ABUSE_LINK")) {
        var deadline = observed.plusSeconds(max);
        if (expiry.isBefore(deadline)) deadline = expiry;
        var factUntil = time(e.get("fact_valid_until"));
        if (factUntil != null && factUntil.isBefore(deadline)) deadline = factUntil;
        if (evidenceValidUntil == null || deadline.isBefore(evidenceValidUntil))
          evidenceValidUntil = deadline;
      }
      switch (kind) {
        case "ACCESS_SCOPE" -> {
          String range = (String) facts.get("audienceClass");
          if ("BROAD".equals(range)
              && (Boolean.TRUE.equals(facts.get("publicAccessConfirmed"))
                  || "COMPLETE".equals(facts.get("coverageStatus")))) ranges.add("BROAD");
          else if ("BOUNDED".equals(range)
              && "COMPLETE".equals(facts.get("coverageStatus"))
              && ((Number) facts.getOrDefault("boundedPrincipalCount", 0)).intValue() > 0)
            ranges.add("BOUNDED");
        }
        case "ASSET_CLASSIFICATION" -> {
          boolean grounded = provenance.assetGrounded(o, sourceRefs, facts);
          classificationPresent |= grounded && !"UNKNOWN".equals(facts.get("environment"));
          minimalAssets &=
              grounded
                  && Boolean.TRUE.equals(facts.get("testOnly"))
                  && !Boolean.TRUE.equals(facts.get("sensitive"))
                  && !Boolean.TRUE.equals(facts.get("important"))
                  && Set.of("DEV", "TEST").contains(facts.get("environment"));
          importantAssets |=
              grounded
                  && ("PROD".equals(facts.get("environment"))
                      || Boolean.TRUE.equals(facts.get("sensitive"))
                      || Boolean.TRUE.equals(facts.get("important")));
          sensitiveAssets |= grounded && Boolean.TRUE.equals(facts.get("sensitive"));
        }
        case "PERMISSION_MAPPING" -> {
          boolean complete = provenance.permissionGrounded(o, sourceRefs);
          for (String coverage :
              List.of(
                  "permissionCoverage",
                  "targetCoverage",
                  "restrictionCoverage",
                  "classificationCoverage")) complete &= "COMPLETE".equals(facts.get(coverage));
          String capability = (String) facts.get("capability");
          if (complete
              && "manual-evidence-v1".equals(e.get("mapping_version"))
              && mappingManifest.get("manualCapabilities") instanceof List<?> supported
              && supported.contains(capability)
              && Set.of("ASSET", "ACCOUNT", "ORGANIZATION").contains(facts.get("targetScope"))) {
            positiveCapabilities.add(capability);
            String impact =
                switch (capability) {
                  case "IDENTITY_ADMINISTRATION",
                          "SECURITY_SETTINGS_WRITE",
                          "RESOURCE_ADMINISTRATION" ->
                      "ADMIN";
                  case "PRODUCTION_DEPLOY" -> "IMPORTANT";
                  case "DATA_WRITE", "RESOURCE_READ" -> importantAssets ? "IMPORTANT" : "LIMITED";
                  case "SENSITIVE_DATA_READ" -> sensitiveAssets ? "IMPORTANT" : "UNKNOWN";
                  case "TEST_RESOURCE_READ" -> "MINIMAL";
                  default -> "UNKNOWN";
                };
            impacts.add(impact);
            if ("UNKNOWN".equals(impact)) permissionIncomplete = true;
          } else {
            permissionIncomplete = true;
            reasons.add("PERMISSION_MAPPING_INCOMPLETE");
            reasons.add("IDENTITY_BINDING_UNRESOLVED");
          }
        }
        case "ABUSE_LINK" -> {
          var manifest = map(policy.get("permission_mapping_manifest").toString());
          Object observers = manifest.get("incidentObservers");
          if (!"MANUAL".equals(e.get("source_kind"))
              && observers instanceof List<?> allowed
              && allowed.contains(e.get("writer_service_id")))
            abuse.add(
                Boolean.TRUE.equals(facts.get("unauthorizedUseConfirmed"))
                    && Boolean.TRUE.equals(facts.get("materialImpactConfirmed"))
                    && Boolean.TRUE.equals(facts.get("credentialLinked"))
                    && Boolean.TRUE.equals(facts.get("occurrenceLinked")));
          else reasons.add("ABUSE_LINKAGE_UNVERIFIED");
        }
        default -> {}
      }
    }
    if (ranges.size() == 1) input.put("exposureRange", ranges.iterator().next());
    else if (ranges.size() > 1) {
      reasons.add("CONFLICTING_EVIDENCE"); reasons.add("ACCESS_EVIDENCE_CONFLICT");
    }
    if (!permissionIncomplete && !impacts.isEmpty() && classificationPresent) {
      String impact =
          impacts.stream()
              .max(
                  Comparator.comparingInt(
                      v ->
                          switch (v) {
                            case "ADMIN" -> 4;
                            case "IMPORTANT" -> 3;
                            case "LIMITED" -> 2;
                            case "MINIMAL" -> 1;
                            default -> 0;
                          }))
              .orElse("UNKNOWN");
      if ((!"MINIMAL".equals(impact) || minimalAssets)) input.put("impact", impact);
      else { reasons.add("CONFLICTING_EVIDENCE"); reasons.add("ASSET_CLASSIFICATION_CONFLICT"); }
    } else if (!impacts.isEmpty()) reasons.add("ASSET_CLASSIFICATION_UNKNOWN");
    if (abuse.contains(true)) {
      input.put("abuse", "CONFIRMED");
      if (!exposure.isEmpty() && "NORMAL".equals(exposure.getFirst().get("decision")))
        reasons.add("EXPOSURE_INCIDENT_CONFLICT");
    }
    if ("NORMAL".equals(status)
        && "BROAD".equals(input.get("exposureRange"))
        && !"CONFIRMED".equals(input.get("abuse"))) {
      input.put("exposure", "UNKNOWN");
      reasons.add("ACCESS_POLICY_CONFLICT");
    }
    var snapshot = new TreeMap<String, Object>();
    snapshot.put("inputs", input);
    snapshot.put("positiveCapabilities", List.copyOf(positiveCapabilities));
    snapshot.put("sourceHeads", heads);
    snapshot.put("evidenceRefs", refs);
    snapshot.put("excludedEvidence", excluded);
    snapshot.put(
        "evidenceValidUntil", evidenceValidUntil == null ? null : evidenceValidUntil.toString());
    snapshot.put("normalizerReasons", List.copyOf(reasons));
    snapshot.put("evaluationAsOf", asOf.toString());
    snapshot.put("evidenceRevision", number(o, "risk_evidence_revision"));
    snapshot.put("credentialRevision", number(o, "credential_revision"));
    snapshot.put("scopeRevision", number(o, "scope_revision"));
    snapshot.put("policyHash", HexFormat.of().formatHex((byte[]) policy.get("content_hash")));
    snapshot.put("engineVersion", policy.get("engine_version"));
    snapshot.put("normalizerVersion", policy.get("normalizer_version"));
    snapshot.put("applicabilityVersion", "risk-applicability-v1");
    snapshot.put("freshnessProfileVersion", policy.get("freshness_profile_version"));
    return snapshot;
  }

  private static Map<String, Object> excluded(Map<String, Object> evidence, String code) {
    return Map.of("evidenceId", evidence.get("evidence_id"), "kind", evidence.get("kind"), "reasonCode", code);
  }

  @SuppressWarnings("unchecked")
  public long assess(long occurrence, long expectedRevision, long job) {
    var o = location(occurrence, true);
    if ("METADATA_ONLY".equals(o.get("component_state"))) return 0;
    if (number(o, "risk_evidence_revision") != expectedRevision)
      throw new IllegalStateException("STALE_BASELINE");
    var policy = activePolicy();
    var asOf = jdbc.queryForObject("SELECT clock_timestamp()", OffsetDateTime.class);
    var snap = snapshot(o, policy, asOf);
    var result =
        new SecretSeverityEngine()
            .evaluate((Map<String, String>) snap.get("inputs"), rules(number(policy, "policy_id")));
    var reasons = new TreeSet<>(result.reasons());
    if ("R99".equals(result.ruleId())) reasons.addAll((List<String>) snap.get("normalizerReasons"));
    snap.put("preConflictInputs", snap.get("inputs"));
    snap.put("inputs", new TreeMap<>(result.inputs()));
    byte[] digest = digest(canonical(snap));
    long id =
        jdbc.queryForObject(
            """
INSERT INTO secret_severity_assessments(record_kind,occurrence_id,credential_set_id,scope_id,occurrence_sequence,policy_id,matched_rule_id,
 assessment_status,severity,input_snapshot,evidence_refs,reason_codes,missing_reason_codes,input_digest,evaluation_as_of,evidence_revision,credential_revision,scope_revision,reason_code,writer_service_id,request_job_id)
VALUES('AUTO_RESULT',?,?,?,?,?,?,?,?,?::jsonb,?::jsonb,?::jsonb,?::jsonb,?,?,?,?,?,'RULE_EVALUATED','ASSESSMENT_WORKER',?)
RETURNING assessment_id
""",
            Long.class,
            occurrence,
            number(o, "credential_set_id"),
            number(o, "scope_id"),
            sequence(occurrence),
            number(policy, "policy_id"),
            result.ruleId(),
            result.status(),
            result.severity(),
            canonical(snap),
            canonical(snap.get("evidenceRefs")),
            canonical(reasons),
            canonical(reasons),
            digest,
            asOf,
            expectedRevision,
            number(o, "credential_revision"),
            number(o, "scope_revision"),
            job);
    apply(o, id, null, false);
    return id;
  }

  public void apply(Map<String, Object> o, long target, Long approval, boolean approved) {
    long occurrence = number(o, "occurrence_id");
    var next =
        jdbc.queryForMap("SELECT * FROM secret_severity_assessments WHERE assessment_id=?", target);
    var heads =
        jdbc.queryForList(
            "SELECT * FROM secret_severity_assessments WHERE occurrence_id=? AND"
                + " record_kind='APPLICATION' ORDER BY occurrence_sequence DESC LIMIT 1",
            occurrence);
    Long previous = null, effective = null;
    String currentSeverity = null;
    String preservedSeverity = null;
    boolean activeOverride = false;
    if (!heads.isEmpty()) {
      var head = heads.getFirst();
      previous = number(head, "assessment_id");
      effective =
          "HOLD".equals(head.get("decision"))
              ? (Long) head.get("previous_effective_assessment_id")
              : "EXPIRE_OVERRIDE".equals(head.get("decision"))
                  ? (Long) head.get("restored_effective_assessment_id")
                  : (Long) head.get("target_assessment_id");
      if (effective != null) {
        var current =
            jdbc.queryForMap(
                "SELECT * FROM secret_severity_assessments WHERE assessment_id=?", effective);
        currentSeverity = (String) current.get("severity");
        activeOverride =
            "OVERRIDE_PROPOSAL".equals(current.get("record_kind")) && overrideEligible(current, o);
        if (activeOverride)
          preservedSeverity = (String) expirationFallback(effective).get("severity");
        if ("OVERRIDE_PROPOSAL".equals(current.get("record_kind"))
            && !activeOverride
            && !Boolean.TRUE.equals(
                jdbc.queryForObject(
                    "SELECT EXISTS(SELECT 1 FROM secret_severity_assessments WHERE"
                        + " record_kind='APPLICATION' AND decision='EXPIRE_OVERRIDE' AND"
                        + " target_assessment_id=?)",
                    Boolean.class,
                    effective))) {
          var fallback = expirationFallback(effective);
          previous =
              insertApplication(
                  o,
                  current,
                  previous,
                  effective,
                  "EXPIRE_OVERRIDE",
                  "OVERRIDE_EXPIRED",
                  null,
                  number(fallback, "assessment_id"));
          effective = number(fallback, "assessment_id");
          currentSeverity = (String) fallback.get("severity");
        }
      }
    }
    boolean hold =
        !approved
            && (SecretSeverityEngine.rank((String) next.get("severity"))
                    < Math.max(
                        SecretSeverityEngine.rank(currentSeverity),
                        SecretSeverityEngine.rank(preservedSeverity))
                || activeOverride
                    && SecretSeverityEngine.rank((String) next.get("severity"))
                        <= SecretSeverityEngine.rank(currentSeverity));
    insertApplication(
        o,
        next,
        previous,
        effective,
        hold ? "HOLD" : "APPLY",
        hold
            ? activeOverride ? "MANUAL_OVERRIDE_ACTIVE" : "DOWNGRADE_REVIEW_REQUIRED"
            : "ASSESSMENT_APPLIED",
        approval);
  }

  public boolean overrideEligible(Map<String, Object> proposal, Map<String, Object> occurrence) {
    return number(proposal, "evidence_revision") == number(occurrence, "risk_evidence_revision")
        && number(proposal, "credential_revision") == number(occurrence, "credential_revision")
        && number(proposal, "scope_revision") == number(occurrence, "scope_revision")
        && Boolean.TRUE.equals(
            jdbc.queryForObject(
                """
SELECT ?::timestamptz>clock_timestamp() AND EXISTS(SELECT 1 FROM secret_severity_policies p WHERE p.policy_id=? AND p.state='ACTIVE')
AND EXISTS(SELECT 1 FROM secret_role_grants WHERE user_id=? AND role='SECURITY' AND revoked_at IS NULL AND(connection_id IS NULL OR connection_id=?))
AND EXISTS(SELECT 1 FROM secret_severity_assessments r JOIN secret_role_grants g ON g.user_id=r.actor_user_id
  WHERE r.record_kind='REVIEW' AND r.target_assessment_id=? AND r.decision='APPROVE' AND g.role='SECURITY' AND g.revoked_at IS NULL AND(g.connection_id IS NULL OR g.connection_id=?))
AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(?::jsonb) ref WHERE NOT EXISTS(SELECT 1 FROM secret_current_risk_evidence e WHERE e.evidence_id=ref::bigint AND e.occurrence_id=? AND(e.expires_at IS NULL OR e.expires_at>clock_timestamp())))
""",
                Boolean.class,
                proposal.get("override_expires_at"),
                proposal.get("policy_id"),
                proposal.get("actor_user_id"),
                occurrence.get("connection_id"),
                proposal.get("assessment_id"),
                occurrence.get("connection_id"),
                proposal.get("evidence_refs").toString(),
                occurrence.get("occurrence_id")));
  }

  private long insertApplication(
      Map<String, Object> o,
      Map<String, Object> next,
      Long previous,
      Long effective,
      String decision,
      String reason,
      Long approval) {
    return insertApplication(o, next, previous, effective, decision, reason, approval, null);
  }

  private long insertApplication(
      Map<String, Object> o,
      Map<String, Object> next,
      Long previous,
      Long effective,
      String decision,
      String reason,
      Long approval,
      Long restored) {
    long occurrence = number(o, "occurrence_id");
    return jdbc.queryForObject(
        """
INSERT INTO secret_severity_assessments(record_kind,occurrence_id,credential_set_id,scope_id,occurrence_sequence,policy_id,
evidence_revision,credential_revision,scope_revision,target_assessment_id,previous_application_id,previous_effective_assessment_id,decision,reason_code,writer_service_id,approval_id,restored_effective_assessment_id)
VALUES('APPLICATION',?,?,?,?,?,?,?,?,?,?,?,?,?,'ASSESSMENT_WORKER',?,?) RETURNING assessment_id
""",
        Long.class,
        occurrence,
        number(o, "credential_set_id"),
        number(o, "scope_id"),
        sequence(occurrence),
        number(next, "policy_id"),
        number(o, "risk_evidence_revision"),
        number(o, "credential_revision"),
        number(o, "scope_revision"),
        number(next, "assessment_id"),
        previous,
        effective,
        decision,
        reason,
        approval,
        restored);
  }

  public Map<String, Object> expirationFallback(long assessment) {
    return jdbc.queryForMap(
        """
WITH RECURSIVE chain AS(
 SELECT x.*,0 AS depth FROM secret_severity_assessments x WHERE assessment_id=?
 UNION ALL SELECT prior.*,chain.depth+1 FROM chain
 JOIN LATERAL(SELECT previous_effective_assessment_id FROM secret_severity_assessments a WHERE a.record_kind='APPLICATION' AND a.decision='APPLY' AND a.target_assessment_id=chain.assessment_id ORDER BY occurrence_sequence LIMIT 1)a ON true
 JOIN secret_severity_assessments prior ON prior.assessment_id=a.previous_effective_assessment_id
 WHERE chain.record_kind='OVERRIDE_PROPOSAL' AND chain.depth<100
)SELECT * FROM chain WHERE depth>0 OR NOT EXISTS(SELECT 1 FROM chain WHERE depth>0) ORDER BY CASE severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END DESC,depth LIMIT 1
""",
        assessment);
  }

  public long sequence(long occurrence) {
    return jdbc.queryForObject(
        "SELECT COALESCE(max(occurrence_sequence),0)+1 FROM secret_severity_assessments WHERE"
            + " occurrence_id=?",
        Long.class,
        occurrence);
  }

  @SuppressWarnings("unchecked")
  public boolean replay(long assessment) {
    var row =
        jdbc.queryForMap(
            "SELECT a.*,p.engine_version,p.normalizer_version FROM secret_severity_assessments a"
                + " JOIN secret_severity_policies p USING(policy_id) WHERE assessment_id=? AND"
                + " record_kind='AUTO_RESULT'",
            assessment);
    if (!"severity-engine-v1".equals(row.get("engine_version"))
        || !"risk-normalizer-v1".equals(row.get("normalizer_version")))
      throw new IllegalStateException("REPLAY_UNAVAILABLE");
    var snap = map(row.get("input_snapshot").toString());
    var result =
        new SecretSeverityEngine()
            .evaluate(
                (Map<String, String>) snap.getOrDefault("preConflictInputs", snap.get("inputs")),
                rules(number(row, "policy_id")));
    var reasons = new TreeSet<>(result.reasons());
    if ("R99".equals(result.ruleId())) reasons.addAll((List<String>) snap.get("normalizerReasons"));
    return result.ruleId().equals(row.get("matched_rule_id"))
        && result.status().equals(row.get("assessment_status"))
        && Objects.equals(result.severity(), row.get("severity"))
        && reasons.equals(
            new TreeSet<>(json.readValue(row.get("reason_codes").toString(), List.class)))
        && MessageDigest.isEqual(digest(canonical(snap)), (byte[]) row.get("input_digest"));
  }

  @SuppressWarnings("unchecked")
  public Map<String, Object> map(String value) {
    return json.readValue(value, Map.class);
  }

  public String canonical(Object value) {
    return json.writeValueAsString(sort(value));
  }

  private Object sort(Object v) {
    if (v instanceof Map<?, ?> m) {
      var s = new TreeMap<String, Object>();
      m.forEach((k, x) -> s.put(k.toString(), sort(x)));
      return s;
    }
    if (v instanceof Collection<?> c) return c.stream().map(this::sort).toList();
    return v;
  }

  public static long number(Map<String, Object> o, String key) {
    return ((Number) o.get(key)).longValue();
  }

  public static OffsetDateTime time(Object value) {
    return value instanceof OffsetDateTime at
        ? at
        : value instanceof java.sql.Timestamp t ? t.toInstant().atOffset(ZoneOffset.UTC) : null;
  }

  public static byte[] digest(String value) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA256_UNAVAILABLE");
    }
  }
}
