package com.logssey.secret.risk;
import com.logssey.secret.evidence.SecretInternalRecord;

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
      List<SecretRiskProvenance.Ref> sourceRefs,
      Long assetId,
      OffsetDateTime applicableFrom,
      OffsetDateTime applicableUntil) {
    public Submission(Long revision, String key, String kind, String subject, OffsetDateTime observed,
        OffsetDateTime until, String ref, Map<String, Object> facts,
        List<SecretRiskProvenance.Ref> sourceRefs, Long assetId) {
      this(revision, key, kind, subject, observed, until, ref, facts, sourceRefs, assetId, null, null);
    }
    public Submission(
        Long revision, String key, String kind, String subject, OffsetDateTime observed,
        OffsetDateTime until, String ref, Map<String, Object> facts,
        List<SecretRiskProvenance.Ref> sourceRefs) {
      this(revision, key, kind, subject, observed, until, ref, facts, sourceRefs, null, null, null);
    }
    public Submission(
        Long revision,
        String key,
        String kind,
        String subject,
        OffsetDateTime observed,
        OffsetDateTime until,
        String ref,
        Map<String, Object> facts) {
      this(revision, key, kind, subject, observed, until, ref, facts, List.of(), null, null, null);
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
    return submit(login,occurrence,r,false);
  }

  public Map<String, Object> submitDraft(String login,long occurrence,Submission r) {
    return submit(login,occurrence,r,true);
  }

  private Map<String,Object> submit(String login,long occurrence,Submission r,boolean draft) {
    if (r == null || r.expectedEvidenceRevision() == null) throw SecretRiskFacts.invalid();
    var actor = access.requirePrincipal(login);
    access.requireOccurrenceRead(actor, occurrence);
    var facts = SecretRiskFacts.validate(r.evidenceType(), r.subject(), r.facts());
    SecretRiskFacts.window(
        r.evidenceType(), r.observedAt(), r.validUntil(), OffsetDateTime.now(ZoneOffset.UTC));
    if ((r.applicableFrom() == null) != (r.applicableUntil() == null)) throw SecretRiskFacts.invalid();
    if (r.applicableFrom() != null
        && (!r.applicableUntil().isAfter(r.applicableFrom())
            || r.applicableFrom().isAfter(r.observedAt())
            || (r.validUntil() != null && r.applicableUntil().isAfter(r.validUntil()))))
      throw SecretRiskFacts.invalid();
    SecretEvidenceRules.reference(r.evidenceRef(), false);
    if (r.assetId() != null
        && (r.assetId() <= 0 || !"ASSET_CLASSIFICATION".equals(r.evidenceType())))
      throw SecretRiskFacts.invalid();
    var refs = new ArrayList<>(r.sourceRefs() == null ? List.<SecretRiskProvenance.Ref>of() : r.sourceRefs());
    if (r.assetId() != null) refs.add(new SecretRiskProvenance.Ref("ASSET", r.assetId(), 1, "CLASSIFIES"));
    if (refs.size() > 30
        || refs.stream()
            .anyMatch(
                ref ->
                    ref == null
                        || ref.type() == null
                        || ref.role() == null
                        || ref.id() <= 0
                        || ref.version() < 0)) throw SecretRiskFacts.invalid();
    final var normalizedRefs =
        refs.stream()
            .distinct()
            .sorted(
                Comparator.comparing(SecretRiskProvenance.Ref::type)
                    .thenComparingLong(SecretRiskProvenance.Ref::id)
                    .thenComparingLong(SecretRiskProvenance.Ref::version)
                    .thenComparing(SecretRiskProvenance.Ref::role))
            .toList();
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
                normalizedRefs,
                r.applicableFrom(), r.applicableUntil()));
    if (r.assetId() != null) safe.add(r.assetId());
    if (draft) safe.add("DRAFT_SUBMISSION");
    return commands.execute(
        actor,
        "RISK_EVIDENCE_SUBMITTED",
        r.idempotencyKey(),
        safe,
        () -> {
          authorizeSubmission(actor, occurrence);
          if (r.assetId() != null && !access.hasGlobalRole(actor, SecretRole.SECURITY))
            throw new ApiException(ErrorCode.FORBIDDEN);
        },
        () -> {
          var o = lock(occurrence, r.expectedEvidenceRevision());
          var sourceSeenAt = SecretRiskAssessmentStore.time(o.get("last_seen_at"));
          if (r.applicableFrom() != null && (sourceSeenAt == null
              || sourceSeenAt.isBefore(r.applicableFrom()) || !sourceSeenAt.isBefore(r.applicableUntil())))
            throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
          boolean security = access.hasConnectionRole(actor, number(o,"connection_id"), SecretRole.SECURITY);
          boolean accepted = security && !draft;
          if (!security
              && !access.hasConnectionRole(
                  actor, number(o, "connection_id"), SecretRole.REMEDIATOR))
            throw new ApiException(ErrorCode.FORBIDDEN);
          Long previousAsset = o.get("asset_id") instanceof Number id ? id.longValue() : null;
          var retractedEvidence = new ArrayList<Long>();
          if (r.assetId() != null) {
            // Locking the chosen registry row serializes its environment with the evidence write.
            var assets = jdbc.queryForList(
                "SELECT a.asset_id,a.provider,a.environment,k.issuer,k.component_state FROM assets a"
                    + " CROSS JOIN secret_credential_sets k WHERE a.asset_id=?"
                    + " AND k.credential_set_id=? FOR SHARE OF a", r.assetId(), o.get("credential_set_id"));
            if (assets.isEmpty()) throw new ApiException(ErrorCode.NOT_FOUND);
            var asset = assets.getFirst();
            if (!Objects.equals(asset.get("provider"), asset.get("issuer"))
                || !Objects.equals(asset.get("environment"), facts.get("environment"))
                || "METADATA_ONLY".equals(asset.get("component_state")))
              throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
            if (!Objects.equals(previousAsset, r.assetId()))
              retractedEvidence.addAll(retractAssetEvidence(o, actor, r.idempotencyKey()));
            jdbc.update("UPDATE secret_occurrences SET asset_id=? WHERE occurrence_id=?", r.assetId(), occurrence);
            o = lock(occurrence, jdbc.queryForObject(
                "SELECT risk_evidence_revision FROM secret_occurrences WHERE occurrence_id=?", Long.class, occurrence));
          }
          try {
            new SecretRiskProvenance(jdbc).validate(o, normalizedRefs);
          } catch (IllegalArgumentException error) {
            throw new ApiException(ErrorCode.EVIDENCE_REQUIRED);
          }
          String payload = commands.json.writeValueAsString(facts);
          String reference=SecretInternalRecord.reference(jdbc,r.evidenceRef(),actor.userId(),"OCCURRENCE",occurrence,r.expectedEvidenceRevision(),"EVIDENCE_SUBMITTED");
          long id =
              jdbc.queryForObject(
                  """
INSERT INTO secret_risk_evidence(record_kind,kind,occurrence_id,credential_set_id,scope_id,source_kind,verification_level,
 safe_payload,source_refs,observed_at,effective_from,expires_at,submitted_by_user_id,reviewed_by_user_id,reason_code,evidence_ref,
 safe_payload_digest,ingestion_key,credential_revision,scope_revision,source_object_version,identity_binding_status,mapping_version,
 fact_valid_from,fact_valid_until,source_presence_observed_at,applicability_basis)
VALUES('ASSERTION',?,?,?,?,'MANUAL',?,?::jsonb,?::jsonb,?,?,?,?,?,'EVIDENCE_SUBMITTED',?,?,?,?,?,?,?,'manual-evidence-v1',?,?,?,?) RETURNING evidence_id
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
                  reference,
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
                      : "NOT_APPLICABLE",
                  r.applicableFrom(), r.applicableUntil(),
                  r.applicableFrom() == null ? null : sourceSeenAt,
                  r.applicableFrom() == null ? null : "EFFECTIVE_INTERVAL");
          var result = new LinkedHashMap<String, Object>(result(occurrence, id, accepted ? "ACCEPTED" : "PENDING"));
          if (r.assetId() != null) {
            result.put("assetId", r.assetId());
            result.put("previousAssetId", previousAsset);
            result.put("retractedEvidenceIds", List.copyOf(retractedEvidence));
          }
          return result;
        });
  }

  private List<Long> retractAssetEvidence(Map<String, Object> o, SecretPrincipal actor, String key) {
    var parents = jdbc.queryForList(
        "SELECT * FROM secret_current_risk_evidence WHERE occurrence_id=?"
            + " AND kind IN('ASSET_CLASSIFICATION','PERMISSION_MAPPING') ORDER BY evidence_id", o.get("occurrence_id"));
    var result = new ArrayList<Long>();
    for (var parent : parents) {
      long parentId = number(parent, "evidence_id");
      jdbc.update("""
INSERT INTO secret_risk_evidence(record_kind,kind,occurrence_id,credential_set_id,scope_id,
 related_evidence_id,source_kind,verification_level,safe_payload,observed_at,effective_from,expires_at,
 submitted_by_user_id,reviewed_by_user_id,reason_code,evidence_ref,safe_payload_digest,ingestion_key,
 credential_revision,scope_revision)
VALUES('RETRACTION',?,?,?,?,?,'MANUAL','MANUAL_ACCEPTED','{}',?,?,?,?,?,'ASSET_LINK_CHANGED',?,?,?,?,?)
""", parent.get("kind"), o.get("occurrence_id"), o.get("credential_set_id"), o.get("scope_id"), parentId,
          parent.get("observed_at"), parent.get("effective_from"), parent.get("expires_at"),
          actor.userId(), actor.userId(), parent.get("evidence_ref"), SecretRiskCommands.digest("{}"),
          HexFormat.of().formatHex(SecretRiskCommands.digest("asset-link:" + actor.userId() + ":" + key + ":" + parentId)),
          o.get("credential_revision"), o.get("revision"));
      result.add(parentId);
    }
    return result;
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
