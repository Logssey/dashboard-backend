package com.logssey.secret.risk;

import static org.assertj.core.api.Assertions.*;

import com.logssey.common.error.*;
import com.logssey.secret.access.SecretAccessService;
import java.time.*;
import java.util.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.testcontainers.postgresql.PostgreSQLContainer;

class SecretRiskEvidenceIntegrationTest {
  static final PostgreSQLContainer POSTGRES = new com.logssey.secret.testing.SecretTestPostgres();
  static JdbcTemplate jdbc;
  static DataSourceTransactionManager manager;
  SecretRiskEvidenceService service;
  long occurrence;

  @BeforeAll
  static void start() {
    POSTGRES.start();
    var ds =
        new DriverManagerDataSource(
            POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    jdbc = new JdbcTemplate(ds);
    manager = new DataSourceTransactionManager(ds);
    Flyway.configure().dataSource(ds).load().migrate();
  }

  @AfterAll
  static void stop() {
    POSTGRES.stop();
  }

  @BeforeEach
  void setup() {
    jdbc.execute("TRUNCATE secret_connections,dashboard_users RESTART IDENTITY CASCADE");
    jdbc.update(
        "INSERT INTO dashboard_users(login_id,password_hash,display_name,role)"
            + " VALUES('security','hash','Security','ADMIN'),('reviewer','hash','Reviewer','ADMIN'),('outsider','hash','Outsider','ADMIN')");
    jdbc.update(
        "INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version)"
            + " VALUES('GITHUB','Fixture','protected','ACTIVE',1)");
    jdbc.update(
        "INSERT INTO"
            + " secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,enabled)"
            + " VALUES(1,'fixture',1,'GITHUB_REPOSITORY_FILES','protected',true)");
    jdbc.update(
        "INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source)"
            + " VALUES(1,'SECURITY',1,1,'MANUAL'),(2,'SECURITY',1,1,'MANUAL')");
    jdbc.update(
        "INSERT INTO"
            + " secret_credential_sets(issuer,credential_type,component_state,fingerprint,fingerprint_key_version,first_seen_at,last_seen_at)"
            + " VALUES('GITHUB','GITHUB_PAT','CONFIRMED',decode(repeat('01',32),'hex'),'fixture',now(),now())");
    occurrence =
        jdbc.queryForObject(
            "INSERT INTO"
                + " secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at)"
                + " VALUES(1,1,1,'protected','L1','UNKNOWN','UNKNOWN','UNKNOWN','PRESENT',now(),now())"
                + " RETURNING occurrence_id",
            Long.class);
    service =
        new SecretRiskEvidenceService(
            jdbc, new SecretAccessService(jdbc), new SecretRiskCommands(jdbc, manager));
  }

  SecretRiskEvidenceService.Submission request(long rev, String key) {
    var now = OffsetDateTime.now(ZoneOffset.UTC);
    return new SecretRiskEvidenceService.Submission(
        rev,
        key,
        "ACCESS_SCOPE",
        "OCCURRENCE",
        now,
        now.plusHours(1),
        "TICKET:SEC-123",
        Map.of(
            "audienceClass",
            "BROAD",
            "coverageStatus",
            "COMPLETE",
            "publicAccessConfirmed",
            true,
            "boundedPrincipalCount",
            0));
  }

  @Test
  void ordinarySecurityAcceptsDirectlyAndIdempotencyDoesNotBypassAcl() {
    var r = request(0, "safe");
    var a = service.submit("security", occurrence, r);
    assertThat(a.get("status")).isEqualTo("ACCEPTED");
    assertThat(service.submit("security", occurrence, r)).isEqualTo(a);
    assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_current_risk_evidence", Long.class))
        .isEqualTo(1);
    assertThat(jdbc.queryForObject("SELECT exposure_status FROM secret_occurrences", String.class))
        .isEqualTo("UNKNOWN");
    assertThat(
            jdbc.queryForObject(
                "SELECT risk_evidence_revision FROM secret_occurrences", Long.class))
        .isEqualTo(1);
    jdbc.update("UPDATE secret_role_grants SET revoked_at=now() WHERE user_id=1");
    assertThatThrownBy(() -> service.submit("security", occurrence, r))
        .isInstanceOf(ApiException.class);
  }

  @Test
  void rejectionAndRetractionAppendWithoutMutatingOriginal() {
    var a = service.submit("security", occurrence, request(0, "first"));
    long id = ((Number) a.get("evidenceId")).longValue();
    service.decide(
        "reviewer",
        occurrence,
        id,
        new SecretRiskEvidenceService.Decision(1L, "reject", "REJECT", "EVIDENCE_INCOMPLETE"));
    assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_current_risk_evidence", Long.class))
        .isZero();
    service.decide(
        "security",
        occurrence,
        id,
        new SecretRiskEvidenceService.Decision(2L, "accept", "ACCEPT", "EVIDENCE_VERIFIED"));
    service.decide(
        "security",
        occurrence,
        id,
        new SecretRiskEvidenceService.Decision(3L, "retract", "RETRACT", "EVIDENCE_RETRACTED"));
    assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_risk_evidence", Long.class))
        .isEqualTo(4);
    assertThatThrownBy(
            () ->
                jdbc.update(
                    "UPDATE secret_risk_evidence SET reason_code='CHANGED' WHERE evidence_id=?",
                    id))
        .isInstanceOf(org.springframework.dao.DataAccessException.class);
  }

  @Test
  void closedFactsAndScopeProtectionRejectUnsafeInputBeforePersistence() {
    var r = request(0, "raw");
    var facts = new HashMap<>(r.facts());
    facts.put("rawKey", "fixture-secret-must-not-persist");
    assertThatThrownBy(
            () ->
                service.submit(
                    "security",
                    occurrence,
                    new SecretRiskEvidenceService.Submission(
                        0L,
                        "bad",
                        r.evidenceType(),
                        r.subject(),
                        r.observedAt(),
                        r.validUntil(),
                        r.evidenceRef(),
                        facts)))
        .isInstanceOf(ApiException.class);
    assertThatThrownBy(() -> service.submit("outsider", occurrence, r))
        .isInstanceOf(ApiException.class);
    assertThatThrownBy(() -> service.submit("security", occurrence, request(99, "stale")))
        .isInstanceOf(ApiException.class);
    assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_risk_evidence", Long.class))
        .isZero();
    assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_command_idempotency", Long.class))
        .isZero();
  }
}
