package com.logssey.secret.risk;

import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.command.SecretCommandExecutor;
import com.logssey.secret.evidence.SecretEvidenceRules;
import com.logssey.secret.risk.core.*;
import java.time.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Service
public class SecretRiskEvidenceService {
  public record Submission(
      Long expectedEvidenceRevision,
      String idempotencyKey,
      String evidenceType,
      String subject,
      OffsetDateTime observedAt,
      OffsetDateTime validUntil,
      String evidenceRef,
      Map<String, Object> facts,
      List<SecretRiskProvenance.Ref> sourceRefs) {
    public Submission(
        Long revision,
        String key,
        String kind,
        String subject,
        OffsetDateTime observed,
        OffsetDateTime until,
        String ref,
        Map<String, Object> facts) {
      this(revision, key, kind, subject, observed, until, ref, facts, List.of());
    }
  }

  public record Decision(
      Long expectedEvidenceRevision, String idempotencyKey, String decision, String reasonCode) {}

  final JdbcTemplate jdbc;
  final SecretAccessService access;
  final SecretRiskCommands commands;

  public SecretRiskEvidenceService(
      JdbcTemplate jdbc, SecretAccessService access, SecretRiskCommands commands) {
    this.jdbc = jdbc;
    this.access = access;
    this.commands = commands;
  }

  public Map<String, Object> submit(String login, long occurrence, Submission r) {
    if (r == null || r.expectedEvidenceRevision() == null) throw SecretRiskFacts.invalid();
    var actor = access.requirePrincipal(login);
    access.requireOccurrenceRead(actor, occurrence);
    var facts = SecretRiskFacts.validate(r.evidenceType(), r.subject(), r.facts());
    SecretRiskFacts.window(
        r.evidenceType(), r.observedAt(), r.validUntil(), OffsetDateTime.now(ZoneOffset.UTC));
    SecretEvidenceRules.reference(r.evidenceRef(), true);
    var refs = r.sourceRefs() == null ? List.<SecretRiskProvenance.Ref>of() : r.sourceRefs();
    if (refs.size() > 30
        || refs.stream()
            .anyMatch(
                ref ->
                    ref == null
                        || ref.type() == null
                        || ref.role() == null
                        || ref.id() <= 0
                        || ref.version() < 0)) throw SecretRiskFacts.invalid();
    refs =
        refs.stream()
            .distinct()
            .sorted(
                Comparator.comparing(SecretRiskProvenance.Ref::type)
                    .thenComparingLong(SecretRiskProvenance.Ref::id)
                    .thenComparingLong(SecretRiskProvenance.Ref::version)
                    .thenComparing(SecretRiskProvenance.Ref::role))
            .toList();
    final var normalizedRefs = refs;
    var safe =
        new ArrayList<Object>(
            Arrays.asList(
                occurrence,
                r.expectedEvidenceRevision(),
                r.evidenceType(),
                r.observedAt(),
                r.validUntil(),
                r.evidenceRef(),
                facts,
                normalizedRefs));
    return commands.execute(
        actor,
        "RISK_EVIDENCE_SUBMITTED",
        r.idempotencyKey(),
        safe,
        () -> authorizeSubmission(actor, occurrence),
        () -> {
          var o = lock(occurrence, r.expectedEvidenceRevision());
          boolean accepted =
              access.hasConnectionRole(actor, number(o, "connection_id"), SecretRole.SECURITY);
          if (!accepted
              && !access.hasConnectionRole(
                  actor, number(o, "connection_id"), SecretRole.REMEDIATOR))
            throw new ApiException(ErrorCode.FORBIDDEN);
          try {
            new SecretRiskProvenance(jdbc).validate(o, normalizedRefs);
          } catch (IllegalArgumentException error) {
            throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
          }
          String payload = commands.json.writeValueAsString(facts);
          long id =
              jdbc.queryForObject(
                  """
INSERT INTO secret_risk_evidence(record_kind,kind,occurrence_id,credential_set_id,scope_id,source_kind,verification_level,
 safe_payload,source_refs,observed_at,effective_from,expires_at,submitted_by_user_id,reviewed_by_user_id,reason_code,evidence_ref,
 safe_payload_digest,ingestion_key,credential_revision,scope_revision,source_object_version,identity_binding_status,mapping_version)
VALUES('ASSERTION',?,?,?,?,'MANUAL',?,?::jsonb,?::jsonb,?,?,?,?,?,'EVIDENCE_SUBMITTED',?,?,?,?,?,?,?,'manual-evidence-v1') RETURNING evidence_id
""",
                  Long.class,
                  r.evidenceType(),
                  occurrence,
                  number(o, "credential_set_id"),
                  number(o, "scope_id"),
                  accepted ? "MANUAL_ACCEPTED" : "MANUAL_SUBMITTED",
                  payload,
                  commands.json.writeValueAsString(normalizedRefs),
                  r.observedAt(),
                  r.observedAt(),
                  r.validUntil(),
                  actor.userId(),
                  accepted ? actor.userId() : null,
                  r.evidenceRef(),
                  SecretRiskCommands.digest(payload),
                  HexFormat.of()
                      .formatHex(
                          SecretRiskCommands.digest(actor.userId() + ":" + r.idempotencyKey())),
                  number(o, "credential_revision"),
                  number(o, "revision"),
                  o.get("latest_object_version"),
                  r.evidenceType().equals("PERMISSION_MAPPING")
                      ? (normalizedRefs.stream()
                              .anyMatch(v -> v.type().equals("VALIDATION_ATTEMPT"))
                          ? "MATCHED"
                          : "UNRESOLVED")
                      : "NOT_APPLICABLE");
          return result(occurrence, id, accepted ? "ACCEPTED" : "PENDING");
        });
  }

  public Map<String, Object> decide(String login, long occurrence, long evidence, Decision r) {
    if (r == null
        || r.expectedEvidenceRevision() == null
        || r.decision() == null
        || r.reasonCode() == null
        || !SecretRiskFacts.EVIDENCE_DECISIONS.contains(r.decision())
        || !SecretRiskFacts.EVIDENCE_REASONS.contains(r.reasonCode()))
      throw SecretRiskFacts.invalid();
    var actor = access.requirePrincipal(login);
    authorize(actor, occurrence);
    return commands.execute(
        actor,
        "RISK_EVIDENCE_DECIDED",
        r.idempotencyKey(),
        List.of(occurrence, evidence, r.expectedEvidenceRevision(), r.decision(), r.reasonCode()),
        () -> authorize(actor, occurrence),
        () -> {
          lock(occurrence, r.expectedEvidenceRevision());
          var rows =
              jdbc.queryForList(
                  "SELECT * FROM secret_risk_evidence WHERE evidence_id=? AND occurrence_id=? AND"
                      + " record_kind='ASSERTION'",
                  evidence,
                  occurrence);
          if (rows.isEmpty()) throw new ApiException(ErrorCode.NOT_FOUND);
          if (Boolean.TRUE.equals(
              jdbc.queryForObject(
                  "SELECT EXISTS(SELECT 1 FROM secret_risk_evidence WHERE related_evidence_id=? AND"
                      + " record_kind='RETRACTION')",
                  Boolean.class,
                  evidence))) throw new ApiException(ErrorCode.CONFLICT);
          var e = rows.getFirst();
          if ("ACCEPT".equals(r.decision())
              && e.get("expires_at") != null
              && !((java.sql.Timestamp) e.get("expires_at")).toInstant().isAfter(Instant.now()))
            throw new ApiException(ErrorCode.UNPROCESSABLE);
          long id =
              jdbc.queryForObject(
                  """
INSERT INTO secret_risk_evidence(record_kind,kind,occurrence_id,credential_set_id,scope_id,related_evidence_id,source_kind,
 verification_level,safe_payload,observed_at,effective_from,expires_at,submitted_by_user_id,reviewed_by_user_id,
 review_decision,reason_code,evidence_ref,safe_payload_digest,ingestion_key,credential_revision,scope_revision)
VALUES(?,?,?,?,?,?,'MANUAL','MANUAL_ACCEPTED','{}',?,?,?,?,?,?,?,?,?,?,?,?) RETURNING evidence_id
""",
                  Long.class,
                  r.decision().equals("RETRACT") ? "RETRACTION" : "REVIEW",
                  e.get("kind"),
                  occurrence,
                  e.get("credential_set_id"),
                  e.get("scope_id"),
                  evidence,
                  e.get("observed_at"),
                  e.get("effective_from"),
                  e.get("expires_at"),
                  actor.userId(),
                  actor.userId(),
                  r.decision().equals("RETRACT") ? null : r.decision(),
                  r.reasonCode(),
                  e.get("evidence_ref"),
                  SecretRiskCommands.digest("{}"),
                  HexFormat.of()
                      .formatHex(
                          SecretRiskCommands.digest(actor.userId() + ":" + r.idempotencyKey())),
                  e.get("credential_revision"),
                  e.get("scope_revision"));
          return result(
              occurrence,
              id,
              r.decision().equals("ACCEPT")
                  ? "ACCEPTED"
                  : r.decision().equals("REJECT") ? "REJECTED" : "RETRACTED");
        });
  }

  void authorize(SecretPrincipal actor, long occurrence) {
    lockAuthorization(actor, occurrence);
    access.requireOccurrenceRead(actor, occurrence);
    access.requireConnectionRole(
        actor,
        jdbc.queryForObject(
            "SELECT connection_id FROM secret_occurrences WHERE occurrence_id=?",
            Long.class,
            occurrence),
        SecretRole.SECURITY);
  }

  private void authorizeSubmission(SecretPrincipal actor, long occurrence) {
    lockAuthorization(actor, occurrence);
    access.requireOccurrenceRead(actor, occurrence);
  }

  private void lockAuthorization(SecretPrincipal actor, long occurrence) {
    if (!TransactionSynchronizationManager.isActualTransactionActive()) return;
    jdbc.queryForList(
        "SELECT g.grant_id FROM secret_role_grants g JOIN secret_occurrences o ON o.occurrence_id=?"
            + " WHERE g.user_id=? AND g.revoked_at IS NULL AND(g.connection_id IS NULL OR"
            + " g.connection_id=o.connection_id) FOR SHARE OF g",
        occurrence,
        actor.userId());
    jdbc.queryForList(
        "SELECT co.occurrence_id FROM secret_case_occurrences co JOIN secret_response_cases c"
            + " USING(case_id) WHERE co.occurrence_id=? FOR SHARE OF co,c",
        occurrence);
    jdbc.queryForList(
        "SELECT user_id FROM secret_team_memberships WHERE user_id=? AND removed_at IS NULL FOR"
            + " SHARE",
        actor.userId());
  }

  Map<String, Object> lock(long occurrence, Long expected) {
    var o =
        jdbc.queryForMap(
            "SELECT o.*,c.credential_revision,s.revision FROM secret_occurrences o JOIN"
                + " secret_credential_sets c USING(credential_set_id) JOIN secret_connection_scopes"
                + " s USING(scope_id) WHERE o.occurrence_id=? FOR UPDATE OF o",
            occurrence);
    SecretCommandExecutor.requireExpectedVersion(expected, number(o, "risk_evidence_revision"));
    return o;
  }

  Map<String, Object> result(long occurrence, long id, String status) {
    return Map.of(
        "occurrenceId",
        occurrence,
        "evidenceId",
        id,
        "status",
        status,
        "evidenceRevision",
        jdbc.queryForObject(
            "SELECT risk_evidence_revision FROM secret_occurrences WHERE occurrence_id=?",
            Long.class,
            occurrence),
        "requiresSnapshotRefresh",
        true);
  }

  static long number(Map<String, Object> r, String key) {
    return ((Number) r.get(key)).longValue();
  }
}
