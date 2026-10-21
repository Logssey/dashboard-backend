package com.logssey.secret.risk;

import static org.assertj.core.api.Assertions.*;

import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.risk.core.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.transaction.support.TransactionTemplate;

class SecretSeverityAssessmentIntegrationTest extends SecretRiskEvidenceIntegrationTest {
  SecretRiskAssessmentStore store;
  SecretRiskQueryService query;

  @BeforeAll
  static void upgrade() {
    Flyway.configure().dataSource(jdbc.getDataSource()).load().migrate();
  }

  @BeforeEach
  void policy() throws Exception {
    String migration =
        Files.readString(
            Path.of("src/main/resources/db/migration/V27__secret_severity_assessment.sql"));
    String seed =
        migration.substring(
            migration.indexOf("INSERT INTO secret_severity_policies"),
            migration.indexOf("CREATE TABLE secret_severity_assessments"));
    jdbc.execute(seed.replace("'severity-v2','ACTIVE'", "'severity-v2','DRAFT'"));
    jdbc.update(
        "UPDATE secret_severity_policies SET"
            + " permission_mapping_manifest=permission_mapping_manifest||'{\"incidentObservers\":[\"fixture-incident-v1\"]}'::jsonb");
    jdbc.update("UPDATE secret_severity_policies SET state='ACTIVE'");
    jdbc.update("UPDATE secret_occurrences SET risk_evidence_revision=0");
    jdbc.update("DELETE FROM secret_jobs WHERE kind='ASSESS'");
    store = new SecretRiskAssessmentStore(jdbc);
    query = new SecretRiskQueryService(jdbc, new SecretAccessService(jdbc));
  }

  long revision() {
    return jdbc.queryForObject(
        "SELECT risk_evidence_revision FROM secret_occurrences WHERE occurrence_id=?",
        Long.class,
        occurrence);
  }

  void exposure(String decision, int version) {
    jdbc.update(
        "INSERT INTO"
            + " secret_exposure_assessments(occurrence_id,from_status,decision,reason_code,scope_origin,scope_revision,decision_source,evidence_refs,actor_user_id,version)"
            + " VALUES(?,'UNKNOWN',?,'UNAPPROVED_SOURCE_LOCATION','PRODUCTION',1,'HUMAN','[]',1,?)",
        occurrence,
        decision,
        version);
  }

  @Test
  void legacyAbnormalDecisionRemainsVisibleWithoutInventingCurrentRiskEvidence() {
    jdbc.update(
        "INSERT INTO"
            + " secret_exposure_assessments(occurrence_id,from_status,decision,reason_code,scope_origin,scope_revision,decision_source,evidence_refs,actor_user_id,version)"
            + " VALUES(?,'UNKNOWN','ABNORMAL','UNAPPROVED_SOURCE_LOCATION','PRODUCTION',NULL,'HUMAN','[]',1,1)",
        occurrence);
    jdbc.update(
        "UPDATE secret_occurrences SET exposure_status='ABNORMAL',policy_recheck_required=true"
            + " WHERE occurrence_id=?",
        occurrence);
    long response =
        jdbc.queryForObject(
            "INSERT INTO"
                + " secret_response_cases(credential_set_id,opening_occurrence_id,opened_by_user_id,opening_reason,case_origin)"
                + " VALUES(1,?,1,'APPROVED_EVIDENCE','PRODUCTION') RETURNING case_id",
            Long.class,
            occurrence);
    jdbc.update(
        "INSERT INTO secret_case_occurrences(case_id,occurrence_id,credential_set_id)"
            + " VALUES(?,?,1)",
        response,
        occurrence);
    evaluate();
    var risk = query.risk("security", occurrence);
    assertThat(risk)
        .containsEntry("assessmentStatus", "UNASSESSED")
        .containsEntry("nextAction", "RECONFIRM_EXPOSURE_DECISION");
    assertThat(((Map<?, ?>) risk.get("latestAutomaticAssessment")).get("ruleId")).isEqualTo("R99");
    assertThat(risk.get("missingReasonCodes").toString())
        .contains("LEGACY_EXPOSURE_SCOPE_UNVERSIONED", "EXPOSURE_RECONFIRMATION_REQUIRED");
    var legacy = (Map<?, ?>) risk.get("legacyExposureAssessment");
    assertThat(legacy.get("decision")).isEqualTo("ABNORMAL");
    assertThat(legacy.get("needsReconfirmation")).isEqualTo(true);
    assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_risk_evidence", Long.class))
        .isZero();
    assertThat(
            jdbc.queryForObject(
                "SELECT count(*) FROM secret_response_cases WHERE closed_at IS NULL", Long.class))
        .isEqualTo(1L);
    assertThat(query.occurrenceRisks(3L, List.of(occurrence))).isEmpty();
  }

  long evaluate() {
    return new TransactionTemplate(manager)
        .execute(
            status -> {
              long job =
                  jdbc.queryForObject("SELECT secret_queue_assessment(?)", Long.class, occurrence);
              return store.assess(occurrence, revision(), job);
            });
  }

  long submit(String kind, Map<String, Object> original) {
    var facts = new HashMap<String, Object>(original);
    var refs = new ArrayList<SecretRiskProvenance.Ref>();
    if (kind.equals("ASSET_CLASSIFICATION")) {
      String env = (String) facts.get("environment");
      Long asset =
          jdbc.queryForObject(
              "INSERT INTO assets(name,provider,asset_type,environment)"
                  + " VALUES(?,'GITHUB','REPOSITORY',?) RETURNING asset_id",
              Long.class,
              UUID.randomUUID().toString(),
              env);
      jdbc.update(
          "UPDATE secret_occurrences SET asset_id=? WHERE occurrence_id=?", asset, occurrence);
      refs.add(new SecretRiskProvenance.Ref("ASSET", asset, 1, "CLASSIFIES"));
    }
    if (kind.equals("PERMISSION_MAPPING")) {
      String impact = (String) facts.remove("impact");
      facts.remove("identityBindingStatus");
      facts.remove("support");
      facts.put(
          "capability",
          switch (impact) {
            case "ADMIN" -> "RESOURCE_ADMINISTRATION";
            case "IMPORTANT" -> "DATA_WRITE";
            case "MINIMAL" -> "TEST_RESOURCE_READ";
            default -> "RESOURCE_READ";
          });
      facts.put("targetScope", "ACCOUNT");
      long identity = identityProof();
      long history = providerReference();
      long assetEvidence =
          jdbc.queryForObject(
              "SELECT max(evidence_id) FROM secret_current_risk_evidence WHERE occurrence_id=? AND"
                  + " kind='ASSET_CLASSIFICATION'",
              Long.class,
              occurrence);
      refs.add(new SecretRiskProvenance.Ref("VALIDATION_ATTEMPT", identity, 1, "BINDS_IDENTITY"));
      refs.add(new SecretRiskProvenance.Ref("RISK_EVIDENCE", assetEvidence, 1, "CLASSIFIES"));
      refs.add(new SecretRiskProvenance.Ref("INVESTIGATION_HISTORY", history, 2, "ASSERTS"));
      refs.add(new SecretRiskProvenance.Ref("INVESTIGATION_HISTORY", history, 2, "LIMITS"));
    }
    if (kind.equals("ABUSE_LINK")) {
      long history = providerReference();
      return jdbc.queryForObject(
          """
INSERT INTO secret_risk_evidence(record_kind,kind,occurrence_id,credential_set_id,scope_id,source_kind,verification_level,
source_refs,safe_payload,observed_at,effective_from,writer_service_id,reason_code,safe_payload_digest,ingestion_key,credential_revision,scope_revision)
VALUES('ASSERTION','ABUSE_LINK',?,1,1,'PROVIDER_OBSERVATION','PROVIDER_OBSERVED',?::jsonb,?::jsonb,now(),now(),'fixture-incident-v1','FIXTURE_INCIDENT',decode(repeat('01',32),'hex'),?,1,1) RETURNING evidence_id
""",
          Long.class,
          occurrence,
          store.canonical(
              List.of(
                  new SecretRiskProvenance.Ref("INVESTIGATION_HISTORY", history, 2, "ASSERTS"))),
          store.canonical(facts),
          UUID.randomUUID().toString());
    }
    for (var reference : refs)
      assertThat(new SecretRiskProvenance(jdbc).valid(store.location(occurrence, false), reference))
          .as(reference.toString())
          .isTrue();
    var now = OffsetDateTime.now(ZoneOffset.UTC);
    return ((Number)
            service
                .submit(
                    "security",
                    occurrence,
                    new SecretRiskEvidenceService.Submission(
                        revision(),
                        UUID.randomUUID().toString(),
                        kind,
                        "OCCURRENCE",
                        now,
                        now.plusHours(1),
                        "TICKET:SEC-123",
                        facts,
                        refs))
                .get("evidenceId"))
        .longValue();
  }

  long providerReference() {
    long task =
        jdbc.queryForObject(
            "INSERT INTO"
                + " secret_investigation_tasks(target_type,occurrence_id,missing_reason_code,creation_source,version)"
                + " VALUES('OCCURRENCE',?,'EVIDENCE_INCOMPLETE','HUMAN_HANDOFF',2) ON"
                + " CONFLICT(occurrence_id,missing_reason_code) WHERE status='OPEN' AND"
                + " target_type='OCCURRENCE' DO UPDATE SET version=2 RETURNING task_id",
            Long.class,
            occurrence);
    long original =
        jdbc.queryForObject(
            "INSERT INTO"
                + " secret_investigation_history(task_id,event_type,actor_user_id,safe_changes,evidence_ref,task_version)"
                + " VALUES(?,'EVIDENCE_ADDED',1,'{\"evidenceKind\":\"PROVIDER_REFERENCE\"}','TICKET:SEC-123',1)"
                + " RETURNING history_id",
            Long.class,
            task);
    return jdbc.queryForObject(
        "INSERT INTO"
            + " secret_investigation_history(task_id,event_type,actor_user_id,safe_changes,evidence_ref,task_version)"
            + " VALUES(?,'EVIDENCE_ACCEPTED',1,jsonb_build_object('acceptedHistoryId',?::bigint),'TICKET:SEC-123',2)"
            + " RETURNING history_id",
        Long.class,
        task,
        original);
  }

  long identityProof() {
    long job =
        jdbc.queryForObject(
            "INSERT INTO"
                + " secret_jobs(kind,connection_id,scheduled_at,available_at,attempt_no,max_attempts,status,finished_at)"
                + " VALUES('FULL_SCAN',1,now(),now(),1,3,'SUCCEEDED',now()) RETURNING job_id",
            Long.class);
    long run =
        jdbc.queryForObject(
            "INSERT INTO"
                + " secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,collection_status,detection_status,validation_status,result_status,finished_at)"
                + " VALUES(?,1,'MANUAL',1,now(),now(),'SUCCEEDED','SUCCEEDED','SUCCEEDED','SUCCEEDED',now())"
                + " RETURNING run_id",
            Long.class,
            job);
    long scope =
        jdbc.queryForObject(
            "INSERT INTO secret_run_scopes(run_id,scope_id,scope_revision,collection_status)"
                + " VALUES(?,1,1,'SUCCEEDED') RETURNING run_scope_id",
            Long.class,
            run);
    long tool =
        jdbc.queryForObject(
            "INSERT INTO secret_tool_runs(run_scope_id,engine,engine_version,config_hash,status)"
                + " VALUES(?,'GITLEAKS','fixture','fixture','SUCCEEDED') RETURNING tool_run_id",
            Long.class,
            scope);
    long finding =
        jdbc.queryForObject(
            "INSERT INTO"
                + " secret_findings(occurrence_id,run_id,tool_run_id,finding_key,rule_id,rule_version,detected_at)"
                + " VALUES(?,?,?,?,'fixture','1',now()) RETURNING finding_id",
            Long.class,
            occurrence,
            run,
            tool,
            UUID.randomUUID().toString());
    return jdbc.queryForObject(
        """
INSERT INTO secret_validation_attempts(credential_set_id,run_id,job_id,validator_id,validator_version,endpoint_class,requested_at,completed_at,provider_checked_at,result,reason_code,
request_sent_at,scope_id,occurrence_id,source_finding_id,credential_revision,scope_revision,validation_revision,validation_approval_revision,validation_profile_version,action_context_digest,dedup_key,cycle_key,attempt_no,reservation_generation,reservation_token,current_eligible,evidence_version)
VALUES(1,?,?,'FIXTURE_IDENTITY','1','FIXTURE_IDENTITY',now(),now(),now(),'VALID','AUTHENTICATED',now(),1,?,?,1,1,1,1,'fixture',decode(repeat('02',32),'hex'),decode(repeat('03',32),'hex'),?,1,1,gen_random_uuid(),false,1) RETURNING attempt_id
""",
        Long.class,
        run,
        job,
        occurrence,
        finding,
        UUID.randomUUID().toString());
  }

  @Test
  void seedAndDbOnlyAssessmentReproduceHighAndHoldWhenEvidenceBecomesUnknown() {
    assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_severity_rules", Long.class))
        .isEqualTo(9);
    exposure("ABNORMAL", 1);
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
        Map.of("environment", "PROD", "sensitive", true, "important", true, "testOnly", false));
    long permission =
        submit(
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
                "ADMIN"));
    long first = evaluate();
    assertThat(
            jdbc.queryForObject(
                "SELECT matched_rule_id FROM secret_severity_assessments WHERE assessment_id=?",
                String.class,
                first))
        .isEqualTo("R03");
    service.decide(
        "security",
        occurrence,
        permission,
        new SecretRiskEvidenceService.Decision(
            revision(), "retractperm", "RETRACT", "EVIDENCE_RETRACTED"));
    long second = evaluate();
    assertThat(
            jdbc.queryForObject(
                "SELECT matched_rule_id FROM secret_severity_assessments WHERE assessment_id=?",
                String.class,
                second))
        .isEqualTo("R99");
    var projected = query.occurrenceRisks(1, List.of(occurrence)).get(occurrence);
    assertThat(projected.get("effectiveSeverity")).isEqualTo("HIGH");
    assertThat(projected.get("held")).isEqualTo(true);
    assertThat(
            jdbc.queryForObject(
                "SELECT count(*) FROM secret_scan_runs WHERE job_id IN(SELECT job_id FROM"
                    + " secret_jobs WHERE kind='ASSESS')",
                Long.class))
        .isZero();
    assertThatThrownBy(
            () ->
                jdbc.update(
                    "UPDATE secret_severity_assessments SET severity='LOW' WHERE assessment_id=?",
                    first))
        .isInstanceOf(org.springframework.dao.DataAccessException.class);
  }

  @Test
  void confirmedIncidentAndNormalConflictCannotEraseCritical() {
    exposure("ABNORMAL", 1);
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
    long critical = evaluate();
    assertThat(
            jdbc.queryForObject(
                "SELECT severity FROM secret_severity_assessments WHERE assessment_id=?",
                String.class,
                critical))
        .isEqualTo("CRITICAL");
    exposure("NORMAL", 2);
    long conflict = evaluate();
    assertThat(
            jdbc.queryForObject(
                "SELECT matched_rule_id FROM secret_severity_assessments WHERE assessment_id=?",
                String.class,
                conflict))
        .isEqualTo("R99");
    assertThat(query.risk("security", occurrence).get("effectiveSeverity")).isEqualTo("CRITICAL");
    assertThat(store.json.writeValueAsString(query.risk("security", occurrence)))
        .contains("EXPOSURE_INCIDENT_CONFLICT")
        .doesNotContain("protected", "fingerprint", "auth_ref");
  }

  @Test
  void queuesDeduplicateAndAclFilteredBulkNeverIncludesForeignLocation() {
    var requests =
        new SecretAssessmentRequests(
            jdbc, new SecretAccessService(jdbc), new SecretRiskCommands(jdbc, manager), service);
    var r = new SecretAssessmentRequests.Request(0L, "request");
    var first = requests.request("security", occurrence, r);
    assertThat(requests.request("security", occurrence, r)).isEqualTo(first);
    assertThat(query.occurrenceRisks(3, List.of(occurrence))).isEmpty();
    assertThat(
            jdbc.queryForObject("SELECT count(*) FROM secret_jobs WHERE kind='ASSESS'", Long.class))
        .isEqualTo(1);
    assertThat(
            jdbc.queryForObject(
                "SELECT count(*) FROM secret_scan_runs WHERE job_id IN(SELECT job_id FROM"
                    + " secret_jobs WHERE kind='ASSESS')",
                Long.class))
        .isZero();
  }

  @Test
  void trustedAccessObservationIsAtomicIdempotentAndLatestStreamSupersedesPublic() {
    long attempt = identityProof();
    long runScope =
        jdbc.queryForObject(
            "SELECT rs.run_scope_id FROM secret_run_scopes rs JOIN secret_validation_attempts a"
                + " USING(run_id) WHERE a.attempt_id=?",
            Long.class,
            attempt);
    var writer = new SecretRiskObservationWriter(jdbc);
    var at = OffsetDateTime.now(ZoneOffset.UTC).withNano(0);
    long first = writer.githubRepositoryAccess(occurrence, runScope, true, true, at);
    long changed = revision();
    assertThat(writer.githubRepositoryAccess(occurrence, runScope, true, true, at))
        .isEqualTo(first);
    assertThat(revision()).isEqualTo(changed);
    assertThatThrownBy(() -> writer.githubRepositoryAccess(occurrence, runScope, false, true, at))
        .isInstanceOf(IllegalArgumentException.class);
    var snap =
        store.snapshot(
            store.location(occurrence, false), store.activePolicy(), OffsetDateTime.now());
    assertThat(((Map<?, ?>) snap.get("inputs")).get("exposureRange")).isEqualTo("BROAD");
    long newer = identityProof();
    long newScope =
        jdbc.queryForObject(
            "SELECT rs.run_scope_id FROM secret_run_scopes rs JOIN secret_validation_attempts a"
                + " USING(run_id) WHERE a.attempt_id=?",
            Long.class,
            newer);
    writer.githubRepositoryAccess(occurrence, newScope, false, true, at.plusSeconds(1));
    snap =
        store.snapshot(
            store.location(occurrence, false), store.activePolicy(), OffsetDateTime.now());
    assertThat(((Map<?, ?>) snap.get("inputs")).get("exposureRange")).isEqualTo("UNKNOWN");
    assertThat(
            jdbc.queryForObject(
                "SELECT count(*) FROM secret_risk_evidence WHERE"
                    + " source_kind='PROVIDER_OBSERVATION'",
                Long.class))
        .isEqualTo(2);
    var tx = new TransactionTemplate(manager);
    long before = revision();
    assertThatThrownBy(
            () ->
                tx.executeWithoutResult(
                    status -> {
                      long rollback = identityProof();
                      long scope =
                          jdbc.queryForObject(
                              "SELECT rs.run_scope_id FROM secret_run_scopes rs JOIN"
                                  + " secret_validation_attempts a USING(run_id) WHERE"
                                  + " a.attempt_id=?",
                              Long.class,
                              rollback);
                      writer.githubRepositoryAccess(
                          occurrence, scope, true, true, at.plusSeconds(2));
                      throw new IllegalStateException("FIXTURE_ROLLBACK");
                    }))
        .isInstanceOf(IllegalStateException.class);
    assertThat(revision()).isEqualTo(before);
    tx.executeWithoutResult(
        status -> {
          jdbc.update("UPDATE secret_connection_scopes SET enabled=false WHERE scope_id=1");
          assertThat(
                  writer.githubRepositoryAccess(
                      occurrence, newScope, true, true, at.plusSeconds(3)))
              .isZero();
          jdbc.update(
              "UPDATE secret_connections SET display_name='Observation skipped safely' WHERE"
                  + " connection_id=1");
        });
    assertThat(
            jdbc.queryForObject(
                "SELECT display_name FROM secret_connections WHERE connection_id=1", String.class))
        .isEqualTo("Observation skipped safely");
  }

  @Test
  void activatedPoliciesAndCrossOccurrenceAssessmentParentsCannotBeRewritten() {
    evaluate();
    for (String sql :
        List.of(
            "UPDATE secret_severity_policies SET state='DRAFT'",
            "UPDATE secret_severity_policies SET normalizer_version='other'",
            "UPDATE secret_severity_policies SET approved_at=now()+interval '1 second'",
            "UPDATE secret_severity_rules SET ordinal=50 WHERE rule_id='R00'"))
      assertThatThrownBy(() -> jdbc.update(sql))
          .isInstanceOf(org.springframework.dao.DataAccessException.class);
    long other =
        jdbc.queryForObject(
            "INSERT INTO"
                + " secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at)"
                + " VALUES(1,1,1,'protected','OTHER','UNKNOWN','UNKNOWN','UNKNOWN','PRESENT',now(),now())"
                + " RETURNING occurrence_id",
            Long.class);
    long target =
        jdbc.queryForObject(
            "SELECT max(assessment_id) FROM secret_severity_assessments WHERE"
                + " record_kind='AUTO_RESULT'",
            Long.class);
    assertThatThrownBy(
            () ->
                jdbc.update(
                    "INSERT INTO"
                        + " secret_severity_assessments(record_kind,occurrence_id,credential_set_id,scope_id,occurrence_sequence,policy_id,evidence_revision,credential_revision,scope_revision,target_assessment_id,previous_application_id,decision,reason_code,writer_service_id)"
                        + " VALUES('APPLICATION',?,1,1,1,1,0,1,1,?,NULL,'APPLY','FIXTURE','FIXTURE')",
                    other,
                    target))
        .isInstanceOf(org.springframework.dao.DataAccessException.class);
    assertThat(query.risk("security", other).get("missingReasonCodes").toString())
        .contains("INITIAL_ASSESSMENT_REQUIRED");
    assertThat(
            jdbc.queryForObject(
                "SELECT count(*) FROM secret_jobs WHERE kind='ASSESS' AND target_occurrence_id=?",
                Long.class,
                other))
        .isEqualTo(1);
  }
}
