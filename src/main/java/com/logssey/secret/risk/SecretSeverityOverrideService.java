package com.logssey.secret.risk;

import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.risk.core.*;
import java.time.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class SecretSeverityOverrideService {
  public record Proposal(
      Long expectedEvidenceRevision,
      String idempotencyKey,
      String targetAssessmentStatus,
      String targetSeverity,
      Long basisAssessmentId,
      String reasonCode,
      List<Long> evidenceIds,
      OffsetDateTime validUntil) {}

  public record Decision(
      Long expectedEvidenceRevision, String idempotencyKey, String decision, String reasonCode) {}

  final JdbcTemplate jdbc;
  final SecretAccessService access;
  final SecretRiskCommands commands;
  final SecretRiskEvidenceService evidence;
  final SecretRiskAssessmentStore store;

  public SecretSeverityOverrideService(
      JdbcTemplate jdbc,
      SecretAccessService access,
      SecretRiskCommands commands,
      SecretRiskEvidenceService evidence) {
    this.jdbc = jdbc;
    this.access = access;
    this.commands = commands;
    this.evidence = evidence;
    this.store = new SecretRiskAssessmentStore(jdbc);
  }

  public Map<String, Object> propose(String login, long occurrence, Proposal r) {
    if (r == null
        || r.expectedEvidenceRevision() == null
        || r.basisAssessmentId() == null
        || r.basisAssessmentId() <= 0
        || r.evidenceIds() == null
        || r.evidenceIds().isEmpty()
        || r.evidenceIds().size() > 30
        || r.evidenceIds().stream().anyMatch(id -> id == null || id <= 0)
        || r.reasonCode() == null
        || r.targetAssessmentStatus() == null
        || !SecretRiskFacts.OVERRIDE_REASONS.contains(r.reasonCode())
        || r.validUntil() == null
        || !r.validUntil().isAfter(OffsetDateTime.now())
        || r.validUntil().isAfter(OffsetDateTime.now().plusDays(7)))
      throw SecretRiskFacts.invalid();
    if (!Set.of("ASSESSED", "NOT_APPLICABLE").contains(r.targetAssessmentStatus())
        || "ASSESSED".equals(r.targetAssessmentStatus()) != (r.targetSeverity() != null)
        || r.targetSeverity() != null && SecretSeverityEngine.rank(r.targetSeverity()) == 0)
      throw SecretRiskFacts.invalid();
    var actor = access.requirePrincipal(login);
    evidence.authorize(actor, occurrence);
    return commands.execute(
        actor,
        "SEVERITY_OVERRIDE_PROPOSED",
        r.idempotencyKey(),
        Arrays.asList(
            occurrence,
            r.expectedEvidenceRevision(),
            r.targetAssessmentStatus(),
            r.targetSeverity(),
            r.basisAssessmentId(),
            r.reasonCode(),
            r.evidenceIds().stream().sorted().distinct().toList(),
            r.validUntil()),
        () -> evidence.authorize(actor, occurrence),
        () -> {
          var o = evidence.lock(occurrence, r.expectedEvidenceRevision());
          var basis = basis(occurrence, r.basisAssessmentId());
          checkBasis(o, basis, r.targetAssessmentStatus(), r.targetSeverity());
          var accepted = acceptedEvidence(occurrence, r.evidenceIds(), r.validUntil());
          var head =
              jdbc.queryForList(
                  "SELECT assessment_id FROM secret_severity_assessments WHERE occurrence_id=? AND"
                      + " record_kind='APPLICATION' ORDER BY occurrence_sequence DESC LIMIT 1",
                  occurrence);
          long id =
              jdbc.queryForObject(
                  """
INSERT INTO secret_severity_assessments(record_kind,occurrence_id,credential_set_id,scope_id,occurrence_sequence,policy_id,assessment_status,severity,
 input_snapshot,evidence_refs,input_digest,evaluation_as_of,evidence_revision,credential_revision,scope_revision,base_auto_assessment_id,previous_application_id,reason_code,actor_user_id,override_expires_at)
VALUES('OVERRIDE_PROPOSAL',?,?,?,?,?,?,?,?::jsonb,?::jsonb,?,?,?,?,?,?,?,?,?,?) RETURNING assessment_id
""",
                  Long.class,
                  occurrence,
                  n(o, "credential_set_id"),
                  n(o, "scope_id"),
                  store.sequence(occurrence),
                  n(basis, "policy_id"),
                  r.targetAssessmentStatus(),
                  r.targetSeverity(),
                  basis.get("input_snapshot").toString(),
                  store.canonical(accepted),
                  SecretRiskAssessmentStore.digest(
                      store.canonical(
                          Arrays.asList(
                              r.targetAssessmentStatus(),
                              r.targetSeverity(),
                              accepted,
                              r.basisAssessmentId()))),
                  basis.get("evaluation_as_of"),
                  r.expectedEvidenceRevision(),
                  n(o, "credential_revision"),
                  n(o, "revision"),
                  r.basisAssessmentId(),
                  head.isEmpty() ? null : head.getFirst().get("assessment_id"),
                  r.reasonCode(),
                  actor.userId(),
                  r.validUntil());
          return result(occurrence, id, "PENDING_APPROVAL", r.expectedEvidenceRevision());
        });
  }

  public Map<String, Object> decide(String login, long occurrence, long id, Decision r) {
    if (r == null
        || r.expectedEvidenceRevision() == null
        || r.decision() == null
        || r.reasonCode() == null
        || !Set.of("APPROVE", "REJECT").contains(r.decision())
        || !SecretRiskFacts.REVIEW_REASONS.contains(r.reasonCode()))
      throw SecretRiskFacts.invalid();
    var actor = access.requirePrincipal(login);
    evidence.authorize(actor, occurrence);
    return commands.execute(
        actor,
        "SEVERITY_OVERRIDE_REVIEWED",
        r.idempotencyKey(),
        List.of(occurrence, id, r.expectedEvidenceRevision(), r.decision(), r.reasonCode()),
        () -> evidence.authorize(actor, occurrence),
        () -> {
          var o = evidence.lock(occurrence, r.expectedEvidenceRevision());
          var rows =
              jdbc.queryForList(
                  "SELECT * FROM secret_severity_assessments WHERE assessment_id=? AND"
                      + " occurrence_id=? AND record_kind='OVERRIDE_PROPOSAL'",
                  id,
                  occurrence);
          if (rows.isEmpty()) throw new ApiException(ErrorCode.NOT_FOUND);
          var proposal = rows.getFirst();
          if (n(proposal, "actor_user_id") == actor.userId())
            throw new ApiException(ErrorCode.FORBIDDEN);
          if (Boolean.TRUE.equals(
              jdbc.queryForObject(
                  "SELECT EXISTS(SELECT 1 FROM secret_severity_assessments WHERE"
                      + " target_assessment_id=? AND record_kind='REVIEW')",
                  Boolean.class,
                  id))) throw new ApiException(ErrorCode.CONFLICT);
          if ("APPROVE".equals(r.decision())) {
            if (n(proposal, "evidence_revision") != r.expectedEvidenceRevision()
                || !SecretRiskAssessmentStore.time(proposal.get("override_expires_at"))
                    .isAfter(OffsetDateTime.now())) throw new ApiException(ErrorCode.CONFLICT);
            var base = basis(occurrence, n(proposal, "base_auto_assessment_id"));
            checkBasis(
                o,
                base,
                (String) proposal.get("assessment_status"),
                (String) proposal.get("severity"));
            var currentHead =
                jdbc.queryForObject(
                    "SELECT max(assessment_id) FROM secret_severity_assessments WHERE"
                        + " occurrence_id=? AND record_kind='APPLICATION'",
                    Long.class,
                    occurrence);
            if (!Objects.equals(currentHead, proposal.get("previous_application_id")))
              throw new ApiException(ErrorCode.CONFLICT);
            var refs = store.json.readValue(proposal.get("evidence_refs").toString(), List.class);
            acceptedEvidence(
                occurrence,
                refs.stream().map(v -> ((Number) v).longValue()).toList(),
                SecretRiskAssessmentStore.time(proposal.get("override_expires_at")));
            var snapshot =
                store.snapshot(
                    store.location(occurrence, false),
                    store.activePolicy(),
                    OffsetDateTime.now(ZoneOffset.UTC));
            @SuppressWarnings("unchecked")
            var inputs = (Map<String, String>) snapshot.get("inputs");
            if ("CONFIRMED".equals(inputs.get("abuse"))
                && SecretSeverityEngine.rank((String) proposal.get("severity")) < 4)
              throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
          }
          long review =
              jdbc.queryForObject(
                  """
INSERT INTO secret_severity_assessments(record_kind,occurrence_id,credential_set_id,scope_id,occurrence_sequence,policy_id,evidence_revision,credential_revision,scope_revision,target_assessment_id,decision,reason_code,actor_user_id)
VALUES('REVIEW',?,?,?,?,?,?,?,?,?,?,?,?) RETURNING assessment_id
""",
                  Long.class,
                  occurrence,
                  n(o, "credential_set_id"),
                  n(o, "scope_id"),
                  store.sequence(occurrence),
                  n(proposal, "policy_id"),
                  n(o, "risk_evidence_revision"),
                  n(o, "credential_revision"),
                  n(o, "revision"),
                  id,
                  r.decision(),
                  r.reasonCode(),
                  actor.userId());
          if ("APPROVE".equals(r.decision()))
            store.apply(store.location(occurrence, false), id, review, true);
          return result(
              occurrence,
              review,
              r.decision().equals("APPROVE") ? "APPROVED" : "REJECTED",
              r.expectedEvidenceRevision());
        });
  }

  Map<String, Object> basis(long occurrence, long id) {
    var rows =
        jdbc.queryForList(
            "SELECT * FROM secret_severity_assessments WHERE assessment_id=? AND occurrence_id=?"
                + " AND record_kind='AUTO_RESULT' AND assessment_id=(SELECT max(assessment_id) FROM"
                + " secret_severity_assessments WHERE occurrence_id=? AND"
                + " record_kind='AUTO_RESULT')",
            id,
            occurrence,
            occurrence);
    if (rows.isEmpty()) throw new ApiException(ErrorCode.CONFLICT);
    return rows.getFirst();
  }

  void checkBasis(Map<String, Object> o, Map<String, Object> base, String status, String severity) {
    if (SecretSeverityEngine.rank(severity) < 4
        && Boolean.TRUE.equals(
            jdbc.queryForObject(
                "SELECT EXISTS(SELECT 1 FROM secret_severity_assessments incident WHERE"
                    + " incident.occurrence_id=? AND incident.record_kind='AUTO_RESULT' AND"
                    + " incident.matched_rule_id='R01' AND EXISTS(SELECT 1 FROM"
                    + " secret_severity_assessments applied WHERE applied.record_kind='APPLICATION'"
                    + " AND applied.decision='APPLY' AND"
                    + " applied.target_assessment_id=incident.assessment_id))",
                Boolean.class,
                n(o, "occurrence_id")))) throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
    if (n(o, "risk_evidence_revision") != n(base, "evidence_revision")
        || n(o, "credential_revision") != n(base, "credential_revision")
        || n(o, "revision") != n(base, "scope_revision")
        || n(store.activePolicy(), "policy_id") != n(base, "policy_id"))
      throw new ApiException(ErrorCode.CONFLICT);
    if ("NOT_APPLICABLE".equals(status)) {
      if (!"R00".equals(base.get("matched_rule_id")))
        throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
    } else if (!"ASSESSED".equals(base.get("assessment_status"))
        || SecretSeverityEngine.rank(severity)
            < SecretSeverityEngine.rank((String) base.get("severity")))
      throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
  }

  List<Long> acceptedEvidence(long occurrence, List<Long> refs, OffsetDateTime until) {
    var ids = refs.stream().distinct().sorted().toList();
    for (long id : ids) {
      var rows =
          jdbc.queryForList(
              """
SELECT e.* FROM secret_current_risk_evidence e JOIN secret_occurrences o USING(occurrence_id)
JOIN secret_credential_sets k ON k.credential_set_id=o.credential_set_id JOIN secret_connection_scopes s ON s.scope_id=o.scope_id
WHERE e.evidence_id=? AND e.occurrence_id=? AND e.credential_revision=k.credential_revision AND e.scope_revision=s.revision
AND(e.kind='ABUSE_LINK' OR e.source_object_version IS NOT DISTINCT FROM o.latest_object_version)
AND(e.expires_at IS NULL OR e.expires_at>clock_timestamp())
""",
              id,
              occurrence);
      if (rows.isEmpty()) throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
      var expiry = SecretRiskAssessmentStore.time(rows.getFirst().get("expires_at"));
      if (expiry != null && until.isAfter(expiry))
        throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
    }
    return ids;
  }

  Map<String, Object> result(long occurrence, long id, String status, long revision) {
    return Map.of(
        "occurrenceId",
        occurrence,
        "assessmentId",
        id,
        "status",
        status,
        "evidenceRevision",
        revision,
        "requiresSnapshotRefresh",
        true);
  }

  static long n(Map<String, Object> row, String key) {
    return ((Number) row.get(key)).longValue();
  }
}
