package com.logssey.secret.risk;

import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.risk.core.*;
import com.logssey.secret.validation.SecretValidationService;
import java.time.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class SecretRiskQueryService {
  final JdbcTemplate jdbc;
  final SecretAccessService access;
  final SecretRiskAssessmentStore store;
  final SecretValidationService validation;

  public SecretRiskQueryService(JdbcTemplate jdbc, SecretAccessService access) {
    this(jdbc, access, new SecretValidationService(jdbc, access, null, false, false));
  }

  @org.springframework.beans.factory.annotation.Autowired
  public SecretRiskQueryService(JdbcTemplate jdbc, SecretAccessService access, SecretValidationService validation) {
    this.jdbc = jdbc;
    this.access = access;
    this.store = new SecretRiskAssessmentStore(jdbc);
    this.validation = validation;
  }

  @org.springframework.transaction.annotation.Transactional(
      readOnly = true, isolation = org.springframework.transaction.annotation.Isolation.REPEATABLE_READ)
  public Map<String, Object> risk(String login, long occurrence) {
    var actor = access.requirePrincipal(login);
    access.requireOccurrenceRead(actor, occurrence);
    var o = store.location(occurrence, false);
    boolean security = access.hasConnectionRole(actor, n(o, "connection_id"), SecretRole.SECURITY);
    boolean metadata = "METADATA_ONLY".equals(o.get("component_state"));
    var result =
        new LinkedHashMap<String, Object>(
            occurrenceRisks(actor.userId(), List.of(occurrence)).get(occurrence));
    var latest =
        jdbc.queryForList(
            "SELECT a.*,p.policy_version FROM secret_severity_assessments a JOIN"
                + " secret_severity_policies p USING(policy_id) WHERE occurrence_id=? AND"
                + " record_kind='AUTO_RESULT' ORDER BY occurrence_sequence DESC LIMIT 1",
            occurrence);
    var reasons = new ArrayList<String>();
    var conflicts = new ArrayList<String>();
    var inputs = new TreeMap<String, Object>();
    if (!latest.isEmpty()) {
      var e = latest.getFirst();
      var snap = store.map(e.get("input_snapshot").toString());
      Object data = snap.get("inputs");
      if (data instanceof Map<?, ?> m) m.forEach((k, v) -> inputs.put(k.toString(), v));
      for (Object code : store.json.readValue(e.get("reason_codes").toString(), List.class)) {
        if (code.toString().contains("CONFLICT")) conflicts.add(code.toString());
        else reasons.add(code.toString());
      }
    }
    if (metadata) reasons.add("METADATA_ONLY");
    if (latest.isEmpty() && !metadata) reasons.add("INITIAL_ASSESSMENT_REQUIRED");
    boolean reconfirmExposure =
        result.get("legacyExposureAssessment") instanceof Map<?, ?> prior
            && Boolean.TRUE.equals(prior.get("needsReconfirmation"));
    if (reconfirmExposure
        && result.get("legacyExposureAssessment") instanceof Map<?, ?> prior
        && prior.get("reasonCodes") instanceof List<?> codes)
      codes.forEach(code -> reasons.add(code.toString()));
    result.put("inputs", inputs);
    result.put("availableSourceRefs", new SecretRiskProvenance(jdbc).available(o));
    result.put("missingReasonCodes", reasons);
    result.put("conflictReasonCodes", conflicts);
    result.put(
        "positiveCapabilities",
        latest.isEmpty()
            ? List.of()
            : store
                .map(latest.getFirst().get("input_snapshot").toString())
                .getOrDefault("positiveCapabilities", List.of()));
    result.put(
        "freshness",
        Map.of(
            "currentEligible",
            Boolean.TRUE.equals(result.get("currentEligible")),
            "profileVersion",
            "risk-freshness-v1"));
    var evidence = new ArrayList<Map<String, Object>>();
    for (var e :
        jdbc.queryForList(
            """
SELECT e.evidence_id,e.kind,e.verification_level,e.observed_at,e.expires_at,e.fact_valid_from,e.fact_valid_until,e.source_presence_observed_at,e.applicability_basis,e.safe_payload::text AS payload,e.evidence_ref,e.source_refs::text AS source_refs,
EXISTS(SELECT 1 FROM secret_current_risk_evidence c WHERE c.evidence_id=e.evidence_id) AS accepted,
EXISTS(SELECT 1 FROM secret_risk_evidence r WHERE r.related_evidence_id=e.evidence_id AND r.record_kind='RETRACTION') AS retracted,(SELECT r.review_decision FROM secret_risk_evidence r WHERE r.related_evidence_id=e.evidence_id AND r.record_kind='REVIEW' ORDER BY r.evidence_id DESC LIMIT 1) AS latest_review
FROM secret_risk_evidence e WHERE e.occurrence_id=? AND e.record_kind='ASSERTION' ORDER BY e.evidence_id DESC LIMIT 100
""",
            occurrence)) {
      var item = new LinkedHashMap<String, Object>();
      item.put("evidenceId", e.get("evidence_id"));
      item.put("type", e.get("kind"));
      item.put("facts", store.map((String) e.get("payload")));
      item.put("evidenceRef", e.get("evidence_ref"));
      item.put("sourceRefs", store.json.readValue(e.get("source_refs").toString(), List.class));
      item.put(
          "verificationLevel",
          Boolean.TRUE.equals(e.get("accepted"))
                  && "MANUAL_SUBMITTED".equals(e.get("verification_level"))
              ? "MANUAL_ACCEPTED"
              : e.get("verification_level"));
      item.put("observedAt", SecretRiskAssessmentStore.time(e.get("observed_at")));
      item.put("validUntil", SecretRiskAssessmentStore.time(e.get("expires_at")));
      item.put("applicableFrom", SecretRiskAssessmentStore.time(e.get("fact_valid_from")));
      item.put("applicableUntil", SecretRiskAssessmentStore.time(e.get("fact_valid_until")));
      item.put("sourcePresenceObservedAt", SecretRiskAssessmentStore.time(e.get("source_presence_observed_at")));
      item.put("applicabilityBasis", e.get("applicability_basis"));
      item.put(
          "status",
          Boolean.TRUE.equals(e.get("retracted"))
              ? "RETRACTED"
              : e.get("expires_at") != null
                      && !SecretRiskAssessmentStore.time(e.get("expires_at"))
                          .isAfter(OffsetDateTime.now())
                  ? "EXPIRED"
                  : Boolean.TRUE.equals(e.get("accepted"))
                      ? "ACCEPTED"
                      : "REJECT".equals(e.get("latest_review")) ? "REJECTED" : "PENDING");
      item.put("canDecide", security && !Boolean.TRUE.equals(e.get("retracted")));
      item.put(
          "allowedDecisionReasonCodes",
          security ? SecretRiskFacts.EVIDENCE_REASONS.stream().sorted().toList() : List.of());
      evidence.add(item);
    }
    result.put("evidenceSummary", evidence);
    result.put("evidenceForms", SecretRiskFacts.FORMS);
    var proposals = new ArrayList<Map<String, Object>>();
    for (var p :
        jdbc.queryForList(
            "SELECT a.* FROM secret_severity_assessments a WHERE occurrence_id=? AND"
                + " record_kind='OVERRIDE_PROPOSAL' AND NOT EXISTS(SELECT 1 FROM"
                + " secret_severity_assessments r WHERE r.record_kind='REVIEW' AND"
                + " r.target_assessment_id=a.assessment_id) ORDER BY occurrence_sequence DESC LIMIT"
                + " 50",
            occurrence)) {
      var item = new LinkedHashMap<String, Object>();
      item.put("assessmentId", p.get("assessment_id"));
      item.put("reasonCode", p.get("reason_code"));
      item.put("evidenceIds", store.json.readValue(p.get("evidence_refs").toString(), List.class));
      item.put("basisAssessmentId", p.get("base_auto_assessment_id"));
      item.put("createdAt", SecretRiskAssessmentStore.time(p.get("created_at")));
      item.put("submittedByUserId", p.get("actor_user_id"));
      item.put("targetAssessmentStatus", p.get("assessment_status"));
      item.put("targetSeverity", p.get("severity"));
      item.put("validUntil", SecretRiskAssessmentStore.time(p.get("override_expires_at")));
      item.put(
          "canReview",
          security
              && n(p, "actor_user_id") != actor.userId()
              && SecretRiskAssessmentStore.time(p.get("override_expires_at"))
                  .isAfter(OffsetDateTime.now(ZoneOffset.UTC)));
      item.put(
          "allowedDecisionReasonCodes", SecretRiskFacts.REVIEW_REASONS.stream().sorted().toList());
      proposals.add(item);
    }
    var targets = new ArrayList<Map<String, Object>>();
    if (Boolean.TRUE.equals(result.get("currentEligible")) && !latest.isEmpty()) {
      var automatic = latest.getFirst();
      if ("ASSESSED".equals(automatic.get("assessment_status")))
        for (String grade : List.of("LOW", "MEDIUM", "HIGH", "CRITICAL")) {
          if (SecretSeverityEngine.rank(grade)
              >= SecretSeverityEngine.rank((String) automatic.get("severity")))
            targets.add(
                Map.of(
                    "assessmentStatus",
                    "ASSESSED",
                    "severity",
                    grade,
                    "basisAssessmentId",
                    automatic.get("assessment_id")));
        }
      else if ("R00".equals(automatic.get("matched_rule_id"))) {
        var target = new LinkedHashMap<String, Object>();
        target.put("assessmentStatus", "NOT_APPLICABLE");
        target.put("severity", null);
        target.put("basisAssessmentId", automatic.get("assessment_id"));
        targets.add(target);
      }
    }
    boolean historicalIncident =
        Boolean.TRUE.equals(
            jdbc.queryForObject(
                "SELECT EXISTS(SELECT 1 FROM secret_severity_assessments incident WHERE"
                    + " incident.occurrence_id=? AND incident.record_kind='AUTO_RESULT' AND"
                    + " incident.matched_rule_id='R01' AND EXISTS(SELECT 1 FROM"
                    + " secret_severity_assessments applied WHERE applied.record_kind='APPLICATION'"
                    + " AND applied.decision='APPLY' AND"
                    + " applied.target_assessment_id=incident.assessment_id))",
                Boolean.class,
                occurrence));
    if (historicalIncident)
      targets.removeIf(target -> SecretSeverityEngine.rank((String) target.get("severity")) < 4);
    result.put("allowedOverrideTargets", targets);
    result.put("overrideMaxDurationDays", 7);
    result.put("overrideProposals", proposals);
    result.put(
        "capabilities",
        Map.of(
            "canSubmitEvidence",
            !metadata
                && (security
                    || access.hasConnectionRole(
                        actor, n(o, "connection_id"), SecretRole.REMEDIATOR)),
            "canRequestAssessment",
            security && !metadata,
            "canProposeOverride",
            security && !metadata && !targets.isEmpty(),
            "canReviewOverrides",
            security));
    result.put(
        "allowedOverrideReasonCodes", SecretRiskFacts.OVERRIDE_REASONS.stream().sorted().toList());
    result.put(
        "allowedEvidenceDecisionReasonCodes",
        SecretRiskFacts.EVIDENCE_REASONS.stream().sorted().toList());
    result.put(
        "nextAction",
        metadata
            ? "NONE"
            : reconfirmExposure
                ? "RECONFIRM_EXPOSURE_DECISION"
                : latest.isEmpty()
                    ? "REQUEST_ASSESSMENT"
                    : conflicts.isEmpty() ? "REVIEW_EVIDENCE" : "INVESTIGATE_CONFLICT");
    var readAt = OffsetDateTime.now(ZoneOffset.UTC);
    var analysisContext = new SecretRiskAnalysisContext(jdbc, store).read(o, result, readAt);
    result.put("analysisContext", analysisContext);
    var authentication = metadata ? Map.<String, Object>of()
        : validation.read(n(o, "credential_set_id"), occurrence, login);
    result.put("riskExperience", new SecretRiskExperience(jdbc, store).read(actor, o, result, analysisContext, authentication, readAt));
    result.put("readAt", readAt);
    return result;
  }

  @org.springframework.transaction.annotation.Transactional(
      readOnly = true, isolation = org.springframework.transaction.annotation.Isolation.REPEATABLE_READ)
  public Map<String, Object> assets(String login, long occurrence, int page, int size) {
    return new SecretRiskAssetService(jdbc, access).list(login, occurrence, page, size);
  }

  public Map<Long, Map<String, Object>> occurrenceRisks(String login, Collection<Long> ids) {
    return occurrenceRisks(access.requirePrincipal(login).userId(), ids);
  }

  public Map<Long, Map<String, Object>> occurrenceRisks(long actorUserId, Collection<Long> ids) {
    if (ids == null || ids.isEmpty()) return Map.of();
    if (ids.size() > 10000 || ids.stream().anyMatch(x -> x == null || x <= 0))
      throw SecretRiskFacts.invalid();
    String sql =
        """
SELECT v.*,o.risk_evidence_revision,k.component_state,l.evidence_revision,l.created_at AS assessed_at,
l.credential_revision AS assessment_credential_revision,k.credential_revision,l.scope_revision AS assessment_scope_revision,s.revision,
e.created_at AS effective_at,ep.policy_version AS effective_policy,e.matched_rule_id AS effective_rule,
e.override_expires_at,l.policy_id,coalesce(storage.policy_result='ALLOWED' AND NOT storage.requires_reassessment,false) AS current_storage_allowed,EXISTS(SELECT 1 FROM secret_severity_policies ap WHERE ap.policy_id=l.policy_id AND ap.state='ACTIVE') AS active_policy,
(l.input_snapshot->>'evidenceValidUntil')::timestamptz<=clock_timestamp() AS expired_after_assessment,
l.input_snapshot->>'applicabilityVersion' AS applicability_version
FROM secret_occurrences o JOIN secret_credential_sets k USING(credential_set_id) JOIN secret_connection_scopes s USING(scope_id)
JOIN secret_current_occurrence_risks v USING(occurrence_id)
LEFT JOIN secret_occurrence_policy_results storage ON storage.occurrence_id=o.occurrence_id
LEFT JOIN secret_severity_assessments l ON l.assessment_id=v.latest_assessment_id
LEFT JOIN secret_severity_assessments e ON e.assessment_id=v.effective_assessment_id
LEFT JOIN secret_severity_policies ep ON ep.policy_id=e.policy_id
WHERE o.occurrence_id IN(:ids) AND
"""
            + SecretOccurrenceAccessSql.predicate("o", ":userId");
    var result = new LinkedHashMap<Long, Map<String, Object>>();
    for (var r :
        new NamedParameterJdbcTemplate(jdbc)
            .queryForList(sql, Map.of("ids", ids, "userId", actorUserId))) {
      boolean metadata = "METADATA_ONLY".equals(r.get("component_state"));
      boolean eligible =
          !metadata
              && Objects.equals(r.get("evidence_revision"), r.get("risk_evidence_revision"))
              && Objects.equals(
                  r.get("assessment_credential_revision"), r.get("credential_revision"))
              && Objects.equals(r.get("assessment_scope_revision"), r.get("revision"))
              && Boolean.TRUE.equals(r.get("active_policy"))
              && "risk-applicability-v1".equals(r.get("applicability_version"))
              && !Boolean.TRUE.equals(r.get("expired_after_assessment"))
              && (!"R00".equals(r.get("rule_id"))
                  || Boolean.TRUE.equals(r.get("current_storage_allowed")));
      var item = new LinkedHashMap<String, Object>();
      item.put("occurrenceId", n(r, "occurrence_id"));
      item.put("evidenceRevision", r.get("risk_evidence_revision"));
      item.put("currentEligible", eligible);
      var latest = new LinkedHashMap<String, Object>();
      latest.put("assessmentId", metadata ? null : r.get("latest_assessment_id"));
      latest.put(
          "assessmentStatus",
          metadata ? "NOT_APPLICABLE" : Objects.toString(r.get("assessment_status"), "UNASSESSED"));
      latest.put("severity", metadata ? null : r.get("severity"));
      latest.put("ruleId", metadata ? null : r.get("rule_id"));
      latest.put("policyVersion", r.get("policy_version"));
      latest.put("assessedAt", SecretRiskAssessmentStore.time(r.get("assessed_at")));
      var effective = new LinkedHashMap<String, Object>();
      effective.put("assessmentId", r.get("effective_assessment_id"));
      effective.put(
          "assessmentStatus",
          Objects.toString(r.get("effective_status"), metadata ? "NOT_APPLICABLE" : "UNASSESSED"));
      effective.put("severity", r.get("effective_severity"));
      effective.put("ruleId", r.get("effective_rule"));
      effective.put("policyVersion", r.get("effective_policy"));
      effective.put("assessedAt", SecretRiskAssessmentStore.time(r.get("effective_at")));
      boolean expiredOverride = Boolean.TRUE.equals(r.get("override_expired"));
      boolean held =
          Boolean.TRUE.equals(r.get("held"))
              || !eligible && r.get("effective_severity") != null
              || expiredOverride;
      effective.put("held", held);
      effective.put(
          "holdReasonCodes",
          held
              ? List.of(
                  expiredOverride
                      ? "OVERRIDE_EXPIRED_REVIEW_REQUIRED"
                      : eligible ? "DOWNGRADE_REVIEW_REQUIRED" : "STALE_EVIDENCE")
              : List.of());
      effective.put("sourceAssessmentId", r.get("effective_assessment_id"));
      effective.put(
          "reviewRequired",
          held && !"MANUAL_OVERRIDE_ACTIVE".equals(r.get("application_reason_code"))
              || expiredOverride);
      item.put("latestAutomaticAssessment", latest);
      item.put("effectiveAssessment", effective);
      item.put(
          "lastConfirmedSeverity",
          r.get("last_confirmed_severity") == null
              ? null
              : Map.of(
                  "severity",
                  r.get("last_confirmed_severity"),
                  "assessmentId",
                  r.get("last_confirmed_assessment_id"),
                  "assessedAt",
                  SecretRiskAssessmentStore.time(r.get("last_confirmed_at"))));
      item.put("assessmentStatus", latest.get("assessmentStatus"));
      item.put("severity", latest.get("severity"));
      item.put("effectiveSeverity", effective.get("severity"));
      item.put("held", held);
      item.put("unassessed", !metadata && (!eligible || Boolean.TRUE.equals(r.get("unassessed"))));
      result.put(n(r, "occurrence_id"), item);
    }
    var priorDecisions = new SecretLegacyExposureFacts(jdbc).read(result.keySet());
    result.forEach(
        (id, item) -> {
          if (priorDecisions.containsKey(id))
            item.put("legacyExposureAssessment", priorDecisions.get(id));
        });
    return result;
  }

  public Map<String, Object> caseSummary(String login, long caseId) {
    var actor = access.requirePrincipal(login);
    var ids =
        jdbc.queryForList(
            "SELECT occurrence_id FROM secret_case_occurrences WHERE case_id=? AND"
                + " response_status<>'RESOLVED'",
            Long.class,
            caseId);
    var visible = occurrenceRisks(actor.userId(), ids);
    if (visible.isEmpty()) throw new ApiException(ErrorCode.NOT_FOUND);
    return aggregate(visible.values());
  }

  public Map<String, Object> credentialSummary(String login, long key) {
    var actor = access.requirePrincipal(login);
    var ids =
        jdbc.queryForList(
            "SELECT DISTINCT co.occurrence_id FROM secret_case_occurrences co JOIN"
                + " secret_response_cases c USING(case_id) WHERE c.credential_set_id=? AND"
                + " c.is_current AND co.response_status<>'RESOLVED'",
            Long.class,
            key);
    return aggregate(occurrenceRisks(actor.userId(), ids).values());
  }

  Map<String, Object> aggregate(Collection<Map<String, Object>> risks) {
    String severity = null;
    long missing = 0, held = 0;
    for (var risk : risks) {
      String s = (String) risk.get("effectiveSeverity");
      if (SecretSeverityEngine.rank(s) > SecretSeverityEngine.rank(severity)) severity = s;
      if (Boolean.TRUE.equals(risk.get("unassessed"))) missing++;
      if (Boolean.TRUE.equals(risk.get("held"))) held++;
    }
    var result = new LinkedHashMap<String, Object>();
    result.put("assessmentStatus", severity == null ? "UNASSESSED" : "ASSESSED");
    result.put("severity", severity);
    result.put("unassessedOccurrenceCount", missing);
    result.put("heldOccurrenceCount", held);
    result.put("coverage", "visible");
    return result;
  }

  public Map<String, Object> history(String login, long occurrence, int page, int size) {
    access.requireOccurrenceRead(access.requirePrincipal(login), occurrence);
    if (page < 0 || size < 1 || size > 100) throw SecretRiskFacts.invalid();
    var rows =
        jdbc.queryForList(
            "SELECT a.*,p.policy_version FROM secret_severity_assessments a JOIN"
                + " secret_severity_policies p USING(policy_id) WHERE occurrence_id=? ORDER BY"
                + " occurrence_sequence DESC LIMIT ? OFFSET ?",
            occurrence,
            size,
            (long) page * size);
    var items = new ArrayList<Map<String, Object>>();
    for (var row : rows) {
      var item = new LinkedHashMap<String, Object>();
      for (var field :
          Map.of(
                  "assessmentId",
                  "assessment_id",
                  "recordKind",
                  "record_kind",
                  "assessmentStatus",
                  "assessment_status",
                  "severity",
                  "severity",
                  "ruleId",
                  "matched_rule_id",
                  "policyVersion",
                  "policy_version",
                  "reasonCode",
                  "reason_code",
                  "decision",
                  "decision")
              .entrySet()) item.put(field.getKey(), row.get(field.getValue()));
      item.put("assessedAt", SecretRiskAssessmentStore.time(row.get("created_at")));
      item.put("createdAt", item.get("assessedAt"));
      items.add(item);
    }
    return Map.of(
        "items",
        items,
        "page",
        page,
        "size",
        size,
        "total",
        jdbc.queryForObject(
            "SELECT count(*) FROM secret_severity_assessments WHERE occurrence_id=?",
            Long.class,
            occurrence));
  }

  static long n(Map<String, Object> r, String key) {
    return ((Number) r.get(key)).longValue();
  }
}
