package com.logssey.secret.validation;

import static org.assertj.core.api.Assertions.*;

import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.command.*;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.util.*;

class SecretValidationIntegrationTest {
    static final PostgreSQLContainer PG = new PostgreSQLContainer("postgres:18.6");
    static JdbcTemplate db;
    static DataSourceTransactionManager tx;
    SecretValidationService service;
    long user, conn, scope, key, occurrence;

    @BeforeAll
    static void start() {
        PG.start();
        var ds = new DriverManagerDataSource(PG.getJdbcUrl(), PG.getUsername(), PG.getPassword());
        db = new JdbcTemplate(ds);
        tx = new DataSourceTransactionManager(ds);
        Flyway.configure().dataSource(ds).load().migrate();
    }

    @AfterAll
    static void stop() {
        PG.stop();
    }

    @BeforeEach
    void setup() {
        db.execute("TRUNCATE secret_connections,dashboard_users RESTART IDENTITY CASCADE");
        user =
                db.queryForObject(
                        "INSERT INTO dashboard_users(login_id,password_hash,display_name,role)"
                                + " VALUES('security','hash','S','ADMIN') RETURNING user_id",
                        Long.class);
        conn =
                db.queryForObject(
                        "INSERT INTO"
                            + " secret_connections(provider,display_name,auth_ref,status,scope_version,validation_enabled,validation_profile_version)"
                            + " VALUES('GITHUB','Safe','test-only','ACTIVE',1,true,'credential-validation-v1')"
                            + " RETURNING connection_id",
                        Long.class);
        db.update(
                "INSERT INTO"
                    + " secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source)"
                    + " VALUES(?,'SECURITY',?,?,'MANUAL')",
                user,
                conn,
                user);
        scope =
                db.queryForObject(
                        "INSERT INTO"
                            + " secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,history_limit,enabled,validation_approved,validation_profile_version,validation_approved_by_user_id,validation_approved_at)"
                            + " VALUES(?,'one',1,'GITHUB_REPOSITORY_FILES','github://acme/repo/main/config/','CURRENT_COMMIT_ONLY',true,true,'credential-validation-v1',?,now())"
                            + " RETURNING scope_id",
                        Long.class,
                        conn,
                        user);
        key =
                db.queryForObject(
                        "INSERT INTO"
                            + " secret_credential_sets(issuer,credential_type,component_state,fingerprint,fingerprint_key_version,masked_label,first_seen_at,last_seen_at)"
                            + " VALUES('AWS','AWS_ACCESS_KEY_PAIR','CONFIRMED',decode(repeat('11',32),'hex'),'v1','AWS"
                            + " masked',now(),now()) RETURNING credential_set_id",
                        Long.class);
        occurrence =
                db.queryForObject(
                        "INSERT INTO"
                            + " secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,location_key,environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at)"
                            + " VALUES(?,?,?,'acme/repo/config/key.env','L1','UNKNOWN','UNKNOWN','UNKNOWN','PRESENT',now(),now())"
                            + " RETURNING occurrence_id",
                        Long.class,
                        key,
                        conn,
                        scope);
        service =
                new SecretValidationService(
                        db,
                        new SecretAccessService(db),
                        new SecretCommandExecutor(db, tx),
                        true,
                        false);
    }

    @Test
    void registersOneRequestAndReplaysAfterCompletionWithoutCreatingNewObservation() {
        var read = service.read(key, occurrence, "security");
        assertThat(read.get("latestAttempt")).isNull();
        assertThat(read.get("lastAuthenticatedAt")).isNull();
        var body =
                Map.<String, Object>of(
                        "occurrenceId",
                        occurrence,
                        "expectedContextVersion",
                        read.get("contextVersion"),
                        "idempotencyKey",
                        "one");
        var first = service.request(key, body, "security");
        assertThat(first).containsEntry("reused", false).containsEntry("status", "PENDING");
        var duplicate = service.request(key, body, "security");
        assertThat(duplicate)
                .containsEntry("reused", true)
                .containsEntry("requestId", first.get("requestId"));
        db.update(
                "UPDATE secret_jobs SET status='SUCCEEDED',finished_at=clock_timestamp() WHERE"
                    + " job_id=?",
                first.get("jobId"));
        assertThat(service.request(key, body, "security"))
                .containsEntry("reused", true)
                .containsEntry("requestId", first.get("requestId"));
        assertThat(db.queryForObject("SELECT count(*) FROM secret_jobs", Long.class)).isEqualTo(1);
        assertThat(service.read(key, occurrence, "security").get("lastAuthenticatedAt")).isNull();
    }

    @Test
    void contextApprovalAndUnknownInputAreCheckedBeforeWork() {
        var read = service.read(key, occurrence, "security");
        var body =
                new HashMap<String, Object>(
                        Map.of(
                                "occurrenceId",
                                occurrence,
                                "expectedContextVersion",
                                read.get("contextVersion"),
                                "idempotencyKey",
                                "safe"));
        body.put("token", "SENTINEL_RAW_DO_NOT_STORE");
        assertThatThrownBy(() -> service.request(key, body, "security"))
                .isInstanceOf(ApiException.class);
        body.remove("token");
        db.update(
                "UPDATE secret_credential_sets SET credential_revision=credential_revision+1 WHERE"
                        + " credential_set_id=?",
                key);
        assertThatThrownBy(() -> service.request(key, body, "security"))
                .isInstanceOf(ValidationApiException.class)
                .extracting(e -> ((ValidationApiException) e).reasonCode())
                .isEqualTo("CONTEXT_CHANGED");
        assertThat(db.queryForObject("SELECT count(*) FROM secret_jobs", Long.class)).isZero();
    }

    @Test
    void policyRevocationCancelsPendingRequestsAndDoesNotEnableGlobalRuntime() {
        var read = service.read(key, occurrence, "security");
        service.request(
                key,
                Map.of(
                        "occurrenceId",
                        occurrence,
                        "expectedContextVersion",
                        read.get("contextVersion"),
                        "idempotencyKey",
                        "verify"),
                "security");
        var policy =
                service.updatePolicy(
                        scope,
                        Map.of(
                                "expectedValidationApprovalRevision",
                                1,
                                "enabled",
                                false,
                                "reasonCode",
                                "VALIDATION_DISABLED",
                                "idempotencyKey",
                                "disable"),
                        "security");
        assertThat(policy)
                .containsEntry("enabled", false)
                .containsEntry("expectedValidationApprovalRevision", 2L);
        assertThat(db.queryForObject("SELECT status FROM secret_jobs", String.class))
                .isEqualTo("CANCELLED");
        var off =
                new SecretValidationService(
                        db,
                        new SecretAccessService(db),
                        new SecretCommandExecutor(db, tx),
                        false,
                        false);
        assertThat(
                        ((Map<?, ?>) off.read(key, occurrence, "security").get("capabilities"))
                                .get("canRequestValidation"))
                .isEqualTo(false);
    }

    @Test
    void operationsAndRevokedGrantsNeverGrantDiscoveryKeyAccess() {
        db.update("UPDATE secret_role_grants SET role='OPERATIONS' WHERE user_id=?", user);
        assertThatThrownBy(() -> service.read(key, occurrence, "security"))
                .isInstanceOf(ApiException.class)
                .extracting(e -> ((ApiException) e).errorCode())
                .isEqualTo(ErrorCode.NOT_FOUND);
        assertThat(service.policy(scope, "security")).containsEntry("canConfigure", false);
        assertThatThrownBy(
                        () ->
                                service.updatePolicy(
                                        scope,
                                        Map.of(
                                                "expectedValidationApprovalRevision",
                                                1,
                                                "enabled",
                                                false,
                                                "reasonCode",
                                                "VALIDATION_DISABLED",
                                                "idempotencyKey",
                                                "disable"),
                                        "security"))
                .isInstanceOf(ApiException.class);
    }

    @Test
    void assessmentJobsDoNotBlockSourceJobsAndCredentialIdentityEpochIsAtomic() {
        db.update(
                "INSERT INTO"
                    + " secret_jobs(kind,purpose,connection_id,target_occurrence_id,scheduled_at,available_at,attempt_no,max_attempts,status)"
                    + " VALUES('ASSESS','SEVERITY_ASSESSMENT',?,?,now(),now(),0,3,'PENDING')",
                conn,
                occurrence);
        var r = service.read(key, occurrence, "security");
        assertThat(
                        service.request(
                                key,
                                Map.of(
                                        "occurrenceId",
                                        occurrence,
                                        "expectedContextVersion",
                                        r.get("contextVersion"),
                                        "idempotencyKey",
                                        "alongside-assess"),
                                "security"))
                .containsEntry("status", "PENDING");
        db.update(
                "UPDATE secret_credential_sets SET fingerprint=decode(repeat('22',32),'hex') WHERE"
                        + " credential_set_id=?",
                key);
        assertThat(
                        db.queryForObject(
                                "SELECT credential_revision FROM secret_credential_sets WHERE"
                                    + " credential_set_id=?",
                                Long.class,
                                key))
                .isEqualTo(2);
    }
}
