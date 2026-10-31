package com.logssey.secret.risk;

import static org.assertj.core.api.Assertions.*;

import com.logssey.common.error.ApiException;
import com.logssey.secret.access.SecretAccessService;
import java.time.*;
import java.util.*;
import org.junit.jupiter.api.*;

class SecretSeverityOverrideIntegrationTest extends SecretSeverityAssessmentIntegrationTest {
  SecretSeverityOverrideService overrides;

  @BeforeEach
  void overrideService() {
    overrides =
        new SecretSeverityOverrideService(
            jdbc, new SecretAccessService(jdbc), new SecretRiskCommands(jdbc, manager), service);
  }

  long limited() {
    exposure(
        "ABNORMAL",
        jdbc.queryForObject(
            "SELECT coalesce(max(version),0)+1 FROM secret_exposure_assessments WHERE"
                + " occurrence_id=?",
            Integer.class,
            occurrence));
    submit(
        "ACCESS_SCOPE",
        Map.of(
            "audienceClass",
            "BOUNDED",
            "coverageStatus",
            "COMPLETE",
            "publicAccessConfirmed",
            false,
            "boundedPrincipalCount",
            2));
    submit(
        "ASSET_CLASSIFICATION",
        Map.of("environment", "DEV", "sensitive", false, "important", false, "testOnly", false));
    return submit(
        "PERMISSION_MAPPING",
        Map.of(
            "identityBindingStatus",
            "MATCHED",
            "support",
            "SUPPORTED",
            "permissionCoverage",
            "COMPLETE",
            "targetCoverage",
            "COMPLETE",
            "restrictionCoverage",
            "COMPLETE",
            "classificationCoverage",
            "COMPLETE",
            "impact",
            "LIMITED"));
  }

  @Test
  void proposalsNeedIndependentApprovalAndPreserveAutomaticResult() {
    long proof = limited(), automatic = evaluate();
    var r =
        new SecretSeverityOverrideService.Proposal(
            revision(),
            "proposal",
            "ASSESSED",
            "HIGH",
            automatic,
            "ADDITIONAL_IMPACT_EVIDENCE",
            List.of(proof),
            OffsetDateTime.now().plusMinutes(20));
    var proposal = overrides.propose("security", occurrence, r);
    long id = ((Number) proposal.get("assessmentId")).longValue();
    assertThat(overrides.propose("security", occurrence, r)).isEqualTo(proposal);
    assertThatThrownBy(
            () ->
                overrides.decide(
                    "security",
                    occurrence,
                    id,
                    new SecretSeverityOverrideService.Decision(
                        revision(), "self", "APPROVE", "EVIDENCE_VERIFIED")))
        .isInstanceOf(ApiException.class);
    overrides.decide(
        "reviewer",
        occurrence,
        id,
        new SecretSeverityOverrideService.Decision(
            revision(), "approve", "APPROVE", "EVIDENCE_VERIFIED"));
    var risk = query.risk("security", occurrence);
    assertThat(((Map<?, ?>) risk.get("latestAutomaticAssessment")).get("severity"))
        .isEqualTo("MEDIUM");
    assertThat(risk.get("effectiveSeverity")).isEqualTo("HIGH");
    assertThat(
            jdbc.queryForObject(
                "SELECT count(*) FROM secret_severity_assessments WHERE record_kind='REVIEW'",
                Long.class))
        .isEqualTo(1);
  }

  @Test
  void changedEvidenceAndUnprovedDowngradeCannotReuseAnApproval() {
    long proof = limited(), automatic = evaluate();
    long proposal =
        ((Number)
                overrides
                    .propose(
                        "security",
                        occurrence,
                        new SecretSeverityOverrideService.Proposal(
                            revision(),
                            "pending",
                            "ASSESSED",
                            "HIGH",
                            automatic,
                            "ADDITIONAL_IMPACT_EVIDENCE",
                            List.of(proof),
                            OffsetDateTime.now().plusMinutes(20)))
                    .get("assessmentId"))
            .longValue();
    service.decide(
        "security",
        occurrence,
        proof,
        new SecretRiskEvidenceService.Decision(
            revision(), "change", "RETRACT", "EVIDENCE_RETRACTED"));
    assertThatThrownBy(
            () ->
                overrides.decide(
                    "reviewer",
                    occurrence,
                    proposal,
                    new SecretSeverityOverrideService.Decision(
                        revision(), "stale", "APPROVE", "EVIDENCE_VERIFIED")))
        .isInstanceOf(ApiException.class);
    assertThat(
            jdbc.queryForObject(
                "SELECT count(*) FROM secret_severity_assessments WHERE record_kind='REVIEW'",
                Long.class))
        .isZero();
  }

  @Test
  void assignedRemediatorSubmitsPendingAndSecurityAcceptanceDoesNotBecomeProviderProof() {
    jdbc.update(
        "INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source)"
            + " VALUES(3,'REMEDIATOR',1,1,'MANUAL')");
    long caseId =
        jdbc.queryForObject(
            "INSERT INTO"
                + " secret_response_cases(credential_set_id,opening_occurrence_id,opened_by_user_id,opening_reason,case_origin)"
                + " VALUES(1,?,1,'FIXTURE','PRODUCTION') RETURNING case_id",
            Long.class,
            occurrence);
    jdbc.update(
        "INSERT INTO"
            + " secret_case_occurrences(case_id,occurrence_id,credential_set_id,assigned_user_id)"
            + " VALUES(?,?,1,3)",
        caseId,
        occurrence);
    var request = request(revision(), "remediator");
    var result = service.submit("outsider", occurrence, request);
    long id = ((Number) result.get("evidenceId")).longValue();
    assertThat(result.get("status")).isEqualTo("PENDING");
    assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_current_risk_evidence", Long.class))
        .isZero();
    service.decide(
        "security",
        occurrence,
        id,
        new SecretRiskEvidenceService.Decision(
            revision(), "accept-material", "ACCEPT", "EVIDENCE_VERIFIED"));
    var risk = query.risk("security", occurrence);
    String json = store.json.writeValueAsString(risk.get("evidenceSummary"));
    assertThat(json)
        .contains("MANUAL_ACCEPTED", "TICKET:SEC-123", "facts")
        .doesNotContain("PROVIDER_OBSERVED");
  }

  @Test
  void temporaryDowngradeCannotBecomePermanentThroughReassessmentOrExpiration() throws Exception {
    limited();
    long admin =
        submit(
            "PERMISSION_MAPPING",
            Map.of(
                "impact",
                "ADMIN",
                "permissionCoverage",
                "COMPLETE",
                "targetCoverage",
                "COMPLETE",
                "restrictionCoverage",
                "COMPLETE",
                "classificationCoverage",
                "COMPLETE"));
    long original = evaluate();
    assertThat(query.risk("security", occurrence).get("effectiveSeverity")).isEqualTo("HIGH");
    service.decide(
        "security",
        occurrence,
        admin,
        new SecretRiskEvidenceService.Decision(
            revision(), "remove-admin", "RETRACT", "EVIDENCE_RETRACTED"));
    long auto = evaluate();
    long proof =
        jdbc.queryForObject(
            "SELECT max(evidence_id) FROM secret_current_risk_evidence WHERE"
                + " kind='PERMISSION_MAPPING'",
            Long.class);
    var until = OffsetDateTime.now().plusSeconds(3);
    long proposal =
        ((Number)
                overrides
                    .propose(
                        "security",
                        occurrence,
                        new SecretSeverityOverrideService.Proposal(
                            revision(),
                            "temporary",
                            "ASSESSED",
                            "MEDIUM",
                            auto,
                            "EXPOSURE_CORRECTED",
                            List.of(proof),
                            until))
                    .get("assessmentId"))
            .longValue();
    overrides.decide(
        "reviewer",
        occurrence,
        proposal,
        new SecretSeverityOverrideService.Decision(
            revision(), "temporary-approve", "APPROVE", "EVIDENCE_VERIFIED"));
    evaluate();
    var live = query.risk("security", occurrence);
    assertThat(live.get("effectiveSeverity")).isEqualTo("MEDIUM");
    assertThat(((Map<?, ?>) live.get("effectiveAssessment")).get("assessmentId"))
        .isEqualTo(proposal);
    Thread.sleep(
        Math.max(
            0, Duration.between(OffsetDateTime.now(), until.plusNanos(100_000_000)).toMillis()));
    for (int poll = 0;
        poll < 100
            && Boolean.TRUE.equals(
                jdbc.queryForObject("SELECT clock_timestamp()<?", Boolean.class, until));
        poll++) Thread.sleep(50);
    var expired = query.risk("security", occurrence);
    assertThat(expired.get("effectiveSeverity")).isEqualTo("HIGH");
    assertThat(((Map<?, ?>) expired.get("effectiveAssessment")).get("assessmentId"))
        .isEqualTo(original);
    evaluate();
    assertThat(query.risk("security", occurrence).get("effectiveSeverity")).isEqualTo("HIGH");
    assertThat(
            jdbc.queryForObject(
                "SELECT count(*) FROM secret_severity_assessments WHERE decision='EXPIRE_OVERRIDE'",
                Long.class))
        .isEqualTo(1);
  }

  @Test
  void historicalConfirmedIncidentCannotBeRefutedWithUnrelatedCurrentEvidence() {
    exposure("ABNORMAL", 1);
    long incident =
        submit(
            "ABUSE_LINK",
            Map.of(
                "unauthorizedUseConfirmed",
                true,
                "materialImpactConfirmed",
                true,
                "credentialLinked",
                true,
                "occurrenceLinked",
                true));
    evaluate();
    service.decide(
        "security",
        occurrence,
        incident,
        new SecretRiskEvidenceService.Decision(
            revision(), "incident-retract", "RETRACT", "EVIDENCE_RETRACTED"));
    long proof = limited();
    long automatic = evaluate();
    assertThatThrownBy(
            () ->
                overrides.propose(
                    "security",
                    occurrence,
                    new SecretSeverityOverrideService.Proposal(
                        revision(),
                        "unrelated-downgrade",
                        "ASSESSED",
                        "MEDIUM",
                        automatic,
                        "EXPOSURE_CORRECTED",
                        List.of(proof),
                        OffsetDateTime.now().plusMinutes(10))))
        .isInstanceOf(ApiException.class);
    assertThat(query.risk("security", occurrence).get("effectiveSeverity")).isEqualTo("CRITICAL");
    assertThat(query.risk("security", occurrence).get("allowedOverrideTargets").toString())
        .doesNotContain("MEDIUM");
  }
}
