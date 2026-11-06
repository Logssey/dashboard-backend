package com.logssey.secretworker.assessment;

import static org.assertj.core.api.Assertions.*;

import java.util.*;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.testcontainers.postgresql.PostgreSQLContainer;

class SecretAssessmentExecutorIntegrationTest {
  @Test
  void leasesAreFencedRetriesAreExclusiveAndDbOnlyExecutionCreatesNoScanRun() throws Exception {
    try (var postgres = new PostgreSQLContainer("postgres:18.6")) {
      postgres.start();
      var ds =
          new DriverManagerDataSource(
              postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword());
      Flyway.configure().dataSource(ds).load().migrate();
      var jdbc = new JdbcTemplate(ds);
      var executor = new SecretAssessmentExecutor(jdbc, new DataSourceTransactionManager(ds));
      jdbc.update(
          "INSERT INTO dashboard_users(login_id,password_hash,display_name,role)"
              + " VALUES('security','hash','Security','ADMIN')");
      jdbc.update(
          "INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version)"
              + " VALUES('GITHUB','Fixture','protected','ACTIVE',1)");
      jdbc.update(
          "INSERT INTO"
              + " secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,enabled)"
              + " VALUES(1,'fixture',1,'GITHUB_REPOSITORY_FILES','protected',true)");
      jdbc.update(
          "INSERT INTO"
              + " secret_credential_sets(issuer,credential_type,component_state,fingerprint,fingerprint_key_version,first_seen_at,last_seen_at)"
              + " VALUES('GITHUB','GITHUB_PAT','CONFIRMED',decode(repeat('01',32),'hex'),'fixture',now(),now())");
      long occurrence =
          jdbc.queryForObject(
              "INSERT INTO"
                  + " secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at)"
                  + " VALUES(1,1,1,'protected','L1','UNKNOWN','UNKNOWN','UNKNOWN','PRESENT',now(),now())"
                  + " RETURNING occurrence_id",
              Long.class);
      long job = jdbc.queryForObject("SELECT secret_queue_assessment(?)", Long.class, occurrence);
      assertThat(jdbc.queryForObject("SELECT secret_queue_assessment(?)", Long.class, occurrence))
          .isEqualTo(job);
      var stale = executor.claim().orElseThrow();
      assertThat(executor.claim()).isEmpty();
      jdbc.update(
          "UPDATE secret_jobs SET lease_until=now()-interval '1 second' WHERE job_id=?", job);
      var owned = executor.claim().orElseThrow();
      assertThat(owned.generation()).isGreaterThan(stale.generation());
      assertThat(executor.execute(stale)).isFalse();
      assertThat(executor.execute(owned)).isTrue();
      assertThat(
              jdbc.queryForObject(
                  "SELECT status FROM secret_jobs WHERE job_id=?", String.class, job))
          .isEqualTo("SUCCEEDED");
      assertThat(
              jdbc.queryForObject(
                  "SELECT count(*) FROM secret_severity_assessments WHERE"
                      + " record_kind='AUTO_RESULT'",
                  Long.class))
          .isEqualTo(1);
      assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_scan_runs", Long.class)).isZero();
      jdbc.update(
          "INSERT INTO"
              + " secret_risk_evidence(record_kind,kind,occurrence_id,credential_set_id,scope_id,source_kind,verification_level,safe_payload,observed_at,effective_from,expires_at,evidence_ref,reason_code,safe_payload_digest,ingestion_key,credential_revision,scope_revision,submitted_by_user_id,fact_valid_from,fact_valid_until,source_presence_observed_at,applicability_basis)"
              + " VALUES('ASSERTION','ACCESS_SCOPE',?,1,1,'MANUAL','MANUAL_ACCEPTED','{\"audienceClass\":\"BROAD\",\"coverageStatus\":\"COMPLETE\",\"publicAccessConfirmed\":true,\"boundedPrincipalCount\":0}',now(),now(),now()+interval"
              + " '1 second','TICKET:SEC-123','FIXTURE',decode(repeat('01',32),'hex'),'expiry-fixture',1,1,1,now()-interval '1 minute',now()+interval '1 second',now(),'EFFECTIVE_INTERVAL')",
          occurrence);
      assertThat(executor.execute(executor.claim().orElseThrow())).isTrue();
      Thread.sleep(1100);
      executor.queueExpired();
      long expiryRevision =
          jdbc.queryForObject(
              "SELECT risk_evidence_revision FROM secret_occurrences WHERE occurrence_id=?",
              Long.class,
              occurrence);
      long jobCount =
          jdbc.queryForObject("SELECT count(*) FROM secret_jobs WHERE kind='ASSESS'", Long.class);
      executor.queueExpired();
      assertThat(
              jdbc.queryForObject(
                  "SELECT risk_evidence_revision FROM secret_occurrences WHERE occurrence_id=?",
                  Long.class,
                  occurrence))
          .isEqualTo(expiryRevision);
      assertThat(
              jdbc.queryForObject(
                  "SELECT count(*) FROM secret_jobs WHERE kind='ASSESS'", Long.class))
          .isEqualTo(jobCount);
      var expiryJob = executor.claim().orElseThrow();
      assertThat(executor.execute(expiryJob)).isTrue();
      executor.queueExpired();
      assertThat(
              jdbc.queryForObject(
                  "SELECT count(*) FROM secret_jobs WHERE kind='ASSESS'", Long.class))
          .isEqualTo(jobCount);
      jdbc.update(
          "UPDATE secret_occurrences SET risk_evidence_revision=risk_evidence_revision+1 WHERE"
              + " occurrence_id=?",
          occurrence);
      var old = executor.claim().orElseThrow();
      jdbc.update(
          "UPDATE secret_occurrences SET risk_evidence_revision=risk_evidence_revision+1 WHERE"
              + " occurrence_id=?",
          occurrence);
      assertThat(executor.execute(old)).isTrue();
      assertThat(
              jdbc.queryForObject(
                  "SELECT last_error_code FROM secret_jobs WHERE job_id=?",
                  String.class,
                  old.jobId()))
          .isEqualTo("STALE_BASELINE");
      assertThat(executor.claim()).isPresent();
    }
  }
}
