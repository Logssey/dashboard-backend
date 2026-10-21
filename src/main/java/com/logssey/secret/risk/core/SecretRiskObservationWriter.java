package com.logssey.secret.risk.core;

import java.time.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;

/** Trusted collector entry point; no HTTP request can choose provider verification levels. */
public final class SecretRiskObservationWriter {
  private final JdbcTemplate jdbc;
  private final SecretRiskAssessmentStore store;
  private final org.springframework.transaction.support.TransactionTemplate tx;

  public SecretRiskObservationWriter(JdbcTemplate jdbc) {
    this.jdbc = jdbc;
    this.store = new SecretRiskAssessmentStore(jdbc);
    this.tx =
        new org.springframework.transaction.support.TransactionTemplate(
            new org.springframework.jdbc.datasource.DataSourceTransactionManager(
                Objects.requireNonNull(jdbc.getDataSource())));
  }

  /**
   * A successful public repository metadata observation proves BROAD. Private alone never proves
   * BOUNDED.
   */
  public long githubRepositoryAccess(
      long occurrence,
      long runScopeId,
      boolean publicRepository,
      boolean metadataComplete,
      OffsetDateTime observedAt) {
    return Objects.requireNonNull(
        tx.execute(
            status ->
                recordGithubAccess(
                    occurrence, runScopeId, publicRepository, metadataComplete, observedAt)));
  }

  private long recordGithubAccess(
      long occurrence,
      long runScopeId,
      boolean publicRepository,
      boolean metadataComplete,
      OffsetDateTime observedAt) {
    var o = store.location(occurrence, true);
    var scopes =
        jdbc.queryForList(
            "SELECT rs.run_scope_id,rs.scope_id,rs.scope_revision,r.connection_id,c.status AS"
                + " connection_status,s.enabled FROM secret_run_scopes rs JOIN secret_scan_runs r"
                + " USING(run_id) JOIN secret_connections c ON c.connection_id=r.connection_id JOIN"
                + " secret_connection_scopes s ON s.scope_id=rs.scope_id WHERE rs.run_scope_id=?"
                + " AND c.provider='GITHUB' AND rs.collection_status='SUCCEEDED' AND EXISTS(SELECT"
                + " 1 FROM secret_findings f JOIN secret_tool_runs t USING(tool_run_id) WHERE"
                + " f.occurrence_id=? AND t.run_scope_id=rs.run_scope_id)",
            runScopeId,
            occurrence);
    var now = jdbc.queryForObject("SELECT clock_timestamp()", OffsetDateTime.class);
    if (scopes.isEmpty() || observedAt == null || observedAt.isAfter(now.plusMinutes(5)))
      throw new IllegalArgumentException("ACCESS_OBSERVATION_CONTEXT_INVALID");
    var source = scopes.getFirst();
    if (SecretRiskAssessmentStore.number(source, "scope_id")
            != SecretRiskAssessmentStore.number(o, "scope_id")
        || SecretRiskAssessmentStore.number(source, "scope_revision")
            != SecretRiskAssessmentStore.number(o, "scope_revision")
        || SecretRiskAssessmentStore.number(source, "connection_id")
            != SecretRiskAssessmentStore.number(o, "connection_id")
        || !"ACTIVE".equals(source.get("connection_status"))
        || !Boolean.TRUE.equals(source.get("enabled"))
        || !observedAt.plusHours(6).isAfter(now)) return 0;
    String ingestion =
        HexFormat.of()
            .formatHex(
                SecretRiskAssessmentStore.digest("github-access:" + occurrence + ":" + runScopeId));
    boolean broad = publicRepository && metadataComplete;
    var facts = new TreeMap<String, Object>();
    facts.put("audienceClass", broad ? "BROAD" : "UNKNOWN");
    facts.put("coverageStatus", metadataComplete ? "COMPLETE" : "PARTIAL");
    facts.put("publicAccessConfirmed", broad);
    facts.put("boundedPrincipalCount", 0);
    String payload = store.canonical(facts);
    var prior =
        jdbc.queryForList(
            "SELECT evidence_id,safe_payload_digest,observed_at FROM secret_risk_evidence WHERE"
                + " scope_id=? AND source_kind='PROVIDER_OBSERVATION' AND ingestion_key=?",
            SecretRiskAssessmentStore.number(o, "scope_id"),
            ingestion);
    if (!prior.isEmpty()) {
      var existing = prior.getFirst();
      if (!java.security.MessageDigest.isEqual(
              (byte[]) existing.get("safe_payload_digest"),
              SecretRiskAssessmentStore.digest(payload))
          || !SecretRiskAssessmentStore.time(existing.get("observed_at"))
              .toInstant()
              .equals(observedAt.toInstant().truncatedTo(java.time.temporal.ChronoUnit.MICROS)))
        throw new IllegalArgumentException("ACCESS_OBSERVATION_REPLAY_CONFLICT");
      return ((Number) existing.get("evidence_id")).longValue();
    }
    return jdbc.queryForObject(
        """
INSERT INTO secret_risk_evidence(record_kind,kind,occurrence_id,credential_set_id,scope_id,source_kind,verification_level,
 source_refs,safe_payload,observed_at,effective_from,expires_at,writer_service_id,reason_code,safe_payload_digest,
 ingestion_key,credential_revision,scope_revision,source_object_version,collector_connection_id,collector_identity_ref,identity_binding_status)
VALUES('ASSERTION','ACCESS_SCOPE',?,?,?,'PROVIDER_OBSERVATION','PROVIDER_OBSERVED',?::jsonb,?::jsonb,?,?,?,'GITHUB_REPOSITORY_METADATA_V1',?,?, ?,?,?,?,?,?,'NOT_APPLICABLE') RETURNING evidence_id
""",
        Long.class,
        occurrence,
        SecretRiskAssessmentStore.number(o, "credential_set_id"),
        SecretRiskAssessmentStore.number(o, "scope_id"),
        store.canonical(
            List.of(
                Map.of(
                    "type",
                    "RUN_SCOPE",
                    "id",
                    runScopeId,
                    "version",
                    SecretRiskAssessmentStore.number(o, "scope_revision"),
                    "role",
                    "ASSERTS"))),
        payload,
        observedAt,
        observedAt,
        observedAt.plusHours(6),
        broad ? "PUBLIC_REPOSITORY_CONFIRMED" : "ACCESS_RANGE_NOT_PROVEN",
        SecretRiskAssessmentStore.digest(payload),
        ingestion,
        SecretRiskAssessmentStore.number(o, "credential_revision"),
        SecretRiskAssessmentStore.number(o, "scope_revision"),
        o.get("latest_object_version"),
        SecretRiskAssessmentStore.number(o, "connection_id"),
        "CONNECTION:" + SecretRiskAssessmentStore.number(o, "connection_id"));
  }
}
