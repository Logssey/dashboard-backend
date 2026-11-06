package com.logssey.secret.validation;

import static org.assertj.core.api.Assertions.*;

import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import com.logssey.secret.command.*;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.dao.DataIntegrityViolationException;
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
    void manualRequestBudgetIsExplicitAndDoesNotConsumeProviderCalls() {
        for (int i = 0; i < 10; i++)
            db.update(
                    "INSERT INTO"
                        + " secret_jobs(kind,purpose,connection_id,target_occurrence_id,requested_by_user_id,scheduled_at,available_at,attempt_no,max_attempts,status,finished_at)"
                        + " VALUES('REVALIDATE','CREDENTIAL_VALIDITY',?,?,?,now(),now(),1,3,'SUCCEEDED',now())",
                    conn,
                    occurrence,
                    user);
        var read = service.read(key, occurrence, "security");
        assertThat(((Map<?, ?>) read.get("capabilities")).get("blockedReasonCodes").toString())
                .contains("RATE_BUDGET_EXHAUSTED");
        assertThatThrownBy(
                        () ->
                                service.request(
                                        key,
                                        Map.of(
                                                "occurrenceId",
                                                occurrence,
                                                "expectedContextVersion",
                                                read.get("contextVersion"),
                                                "idempotencyKey",
                                                "over-budget"),
                                        "security"))
                .isInstanceOf(ValidationRateLimitException.class);
    }

    @Test
    void githubSupportIsVisibleWhileGlobalActivationRemainsOff() {
        db.update(
                "UPDATE secret_credential_sets SET"
                        + " issuer='GITHUB',credential_type='GITHUB_CLASSIC_PAT'");
        var read = service.read(key, occurrence, "security");
        assertThat(((Map<?, ?>) read.get("support")).get("status")).isEqualTo("SUPPORTED");
        assertThat(((Map<?, ?>) read.get("capabilities")).get("blockedReasonCodes").toString())
                .contains("DISABLED");
        assertThat(read.get("lastConclusiveValidation")).isNull();
    }

    @Test
    void notionCanBeManuallyRevalidatedFromGitHubWhenOtherValidatorsAreDisabled() {
        useNotionCredential();
        var read = service.read(key, occurrence, "security");
        assertThat(((Map<?, ?>) read.get("support")).get("status"))
                .isEqualTo("SUPPORTED");
        assertThat(((Map<?, ?>) read.get("support")).get("methods"))
                .isEqualTo(List.of("NOTION_GET_SELF"));
        assertThat(((Map<?, ?>) read.get("capabilities")).get("canRequestValidation"))
                .isEqualTo(true);
        assertThat(service.policy(scope, "security")).containsEntry("profileStatus", "ENABLED");
        assertThat(request("notion-github")).containsEntry("status", "PENDING");
        assertThat(db.queryForObject("SELECT count(*) FROM secret_validation_attempts", Long.class))
                .isZero();
        assertThat(db.queryForObject("SELECT expected_context::text FROM secret_jobs", String.class))
                .doesNotContain("ntn_", "secret_");
    }

    @Test
    void credentialsFromNotionRequireAnApprovedCurrentPageAndAnIndependentCollectionOptIn() {
        db.update(
                "UPDATE secret_connections SET provider='NOTION',auth_ref='notion-internal:default'"
                    + " WHERE connection_id=?",
                conn);
        db.update(
                "UPDATE secret_connection_scopes SET"
                    + " content_type='NOTION_PAGE_CONTENT',history_limit='CURRENT_VERSION_ONLY',"
                    + " approved_ref='notion://pages/11111111-2222-3333-4444-555555555555' WHERE"
                    + " scope_id=?",
                scope);
        db.update(
                "UPDATE secret_occurrences SET"
                    + " source_object_ref='notion/pages/11111111-2222-3333-4444-555555555555/blocks/66666666-7777-8888-9999-aaaaaaaaaaaa'"
                    + " WHERE occurrence_id=?",
                occurrence);
        service =
                new SecretValidationService(
                        db,
                        new SecretAccessService(db),
                        new SecretCommandExecutor(db, tx),
                        true,
                        false,
                        false,
                        false,
                        false,
                        false);
        assertThat(
                        ((Map<?, ?>) service.read(key, occurrence, "security").get("capabilities"))
                                .get("blockedReasonCodes")
                                .toString())
                .contains("SOURCE_UNAVAILABLE");
        service =
                new SecretValidationService(
                        db,
                        new SecretAccessService(db),
                        new SecretCommandExecutor(db, tx),
                        true,
                        false,
                        false,
                        false,
                        false,
                        true);
        assertThat(
                        ((Map<?, ?>) service.read(key, occurrence, "security").get("capabilities"))
                                .get("canRequestValidation"))
                .isEqualTo(true);
        var retryAt =
                db.queryForObject(
                        """
                        INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version,source_retry_at,source_retry_reason)
                        VALUES('NOTION','Other page source','notion-internal:default','ACTIVE',1,
                          clock_timestamp()+interval '20 minutes','NOTION_RATE_LIMITED') RETURNING source_retry_at
                        """,
                        java.time.OffsetDateTime.class);
        var request = request("notion-source-aws-key");
        assertThat(request).containsEntry("status", "PENDING");
        assertThat(((java.sql.Timestamp) request.get("availableAt")).toInstant())
                .isEqualTo(retryAt.toInstant());
        assertThat(
                        db.queryForObject(
                                "SELECT available_at FROM secret_jobs WHERE connection_id=?",
                                java.time.OffsetDateTime.class,
                                conn))
                .isEqualTo(retryAt);
        var extended =
                db.queryForObject(
                        "UPDATE secret_connections SET source_retry_at=source_retry_at+interval '1"
                            + " minute' WHERE connection_id<>? RETURNING source_retry_at",
                        java.time.OffsetDateTime.class,
                        conn);
        var status = service.requestStatus(((Number) request.get("jobId")).longValue(), "security");
        assertThat(((java.sql.Timestamp) status.get("availableAt")).toInstant())
                .isEqualTo(extended.toInstant());
        var latest = (Map<?, ?>) service.read(key, occurrence, "security").get("latestRequest");
        assertThat(((java.sql.Timestamp) latest.get("availableAt")).toInstant())
                .isEqualTo(extended.toInstant());
        db.update(
                "UPDATE secret_connection_scopes SET history_limit='ALL_VERSIONS' WHERE scope_id=?",
                scope);
        assertThat(
                        ((Map<?, ?>) service.read(key, occurrence, "security").get("capabilities"))
                                .get("blockedReasonCodes")
                                .toString())
                .contains("UNSUPPORTED_SOURCE");
    }

    @Test
    void notionCanBeManuallyRevalidatedFromApprovedAwsContent() {
        useNotionCredential();
        db.update("UPDATE secret_connections SET provider='AWS' WHERE connection_id=?", conn);
        db.update("UPDATE secret_connection_scopes SET content_type='AWS_S3_OBJECT_CONTENT',"
                + " approved_ref='s3://approved-bucket/config/' WHERE scope_id=?", scope);
        assertThat(request("notion-aws")).containsEntry("status", "PENDING");
    }

    @Test
    void notionActivationAndSourceSupportRemainIndependent() {
        useNotionCredential();
        var disabled = new SecretValidationService(db, new SecretAccessService(db),
                new SecretCommandExecutor(db, tx), true, true, false, true, true);
        assertThat(((Map<?, ?>) disabled.read(key, occurrence, "security").get("capabilities"))
                .get("blockedReasonCodes").toString()).contains("DISABLED");
        var sourceDisabled = new SecretValidationService(db, new SecretAccessService(db),
                new SecretCommandExecutor(db, tx), false, false, true, false, true);
        assertThat(((Map<?, ?>) sourceDisabled.read(key, occurrence, "security").get("capabilities"))
                .get("blockedReasonCodes").toString()).contains("SOURCE_UNAVAILABLE");
        db.update("UPDATE secret_connections SET provider='NOTION' WHERE connection_id=?", conn);
        db.update("UPDATE secret_connection_scopes SET content_type='NOTION_PAGE' WHERE scope_id=?", scope);
        assertThat(((Map<?, ?>) service.read(key, occurrence, "security").get("capabilities"))
                .get("blockedReasonCodes").toString()).contains("UNSUPPORTED_SOURCE");
        assertThatThrownBy(() -> request("unsupported-notion-source"))
                .isInstanceOf(ValidationApiException.class);
        assertThat(db.queryForObject("SELECT count(*) FROM secret_jobs", Long.class)).isZero();
        db.update("UPDATE secret_credential_sets SET credential_type='NOTION_PAT' WHERE credential_set_id=?", key);
        assertThat(((Map<?, ?>) service.read(key, occurrence, "security").get("support")).get("status"))
                .isEqualTo("UNSUPPORTED");
    }

    @Test
    void notionIdentityRequiresRegisteredCurrentAuthenticationAndVersionedSafeClaims() {
        useNotionCredential();
        long attempt = completedNotionObservation();
        String botId = "11111111-2222-3333-4444-555555555555";
        String insert = """
                INSERT INTO secret_credential_identities(validation_attempt_id,occurrence_id,
                  credential_set_id,credential_revision,scope_revision,provider,principal_type,
                  principal_ref,principal_id,safe_claims,observed_at,expires_at)
                SELECT attempt_id,occurrence_id,credential_set_id,credential_revision,scope_revision,
                  'NOTION','NOTION_BOT',?,?,?::jsonb,provider_checked_at,provider_checked_at+interval '6 hours'
                FROM secret_validation_attempts WHERE attempt_id=?
                """;
        db.update("UPDATE secret_validation_attempts SET validator_id='AWS_STS_GET_CALLER_IDENTITY' WHERE attempt_id=?", attempt);
        assertThatThrownBy(() -> db.update(insert, "notion-bot:" + botId, botId,
                "{\"schemaVersion\":1}", attempt))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("IDENTITY_VALIDATION_PARENT");
        db.update("UPDATE secret_validation_attempts SET validator_id='NOTION_GET_SELF' WHERE attempt_id=?", attempt);
        assertThatThrownBy(() -> db.update(insert, "notion-bot:" + botId, botId,
                "{\"schemaVersion\":1,\"token\":\"SENTINEL_RAW_DO_NOT_STORE\"}", attempt))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("ck_secret_notion_identity_claims");
        assertThatThrownBy(() -> db.update(insert, "notion-bot:66666666-7777-8888-9999-aaaaaaaaaaaa", botId,
                "{\"schemaVersion\":1}", attempt))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("ck_secret_identity_provider_binding");
        String expired = insert.replace("provider_checked_at+interval '6 hours'", "provider_checked_at");
        assertThatThrownBy(() -> db.update(expired, "notion-bot:" + botId, botId,
                "{\"schemaVersion\":1}", attempt))
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasMessageContaining("secret_credential_identities_check");
        assertThat(db.update(insert, "notion-bot:" + botId, botId,
                "{\"schemaVersion\":1,\"ownerType\":\"workspace\"}", attempt)).isEqualTo(1);
        assertThat(db.queryForObject("SELECT account_ref FROM secret_credential_identities", String.class))
                .isNull();
        var read = service.read(key, occurrence, "security");
        assertThat(((Map<?, ?>) read.get("latestAttempt")).get("method")).isEqualTo("NOTION_GET_SELF");
        assertThat(((Map<?, ?>) read.get("latestAttempt")).get("result")).isEqualTo("VALID");
        assertThat(read.get("lastAuthenticatedAt")).isNotNull();
        var history = (List<?>) service.history(key, occurrence, 0, 20, "security").get("items");
        assertThat(history).hasSize(1);
        assertThat(history.getFirst().toString()).contains("NOTION_GET_SELF")
                .doesNotContain("SENTINEL_RAW", "notion-bot:", botId);
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
    void retryProgressAndTerminalRequestsAreVisibleWithoutAnInventedFutureRetry() {
        var before = service.read(key, occurrence, "security");
        var request = service.request(key, Map.of("occurrenceId", occurrence,
                "expectedContextVersion", before.get("contextVersion"), "idempotencyKey", "retry-progress"), "security");
        long job = ((Number)request.get("requestId")).longValue();
        assertThat(request).containsEntry("attemptNo", 0).containsEntry("maxAttempts", 3)
                .containsEntry("nextRetryAt", null);
        db.update("UPDATE secret_jobs SET attempt_no=1,available_at=clock_timestamp()+interval '2 minutes' WHERE job_id=?", job);
        var retry = service.requestStatus(job, "security");
        assertThat(retry).containsEntry("attemptNo", 1);
        assertThat(retry.get("nextRetryAt")).isEqualTo(retry.get("availableAt")).isNotNull();
        var observationTime = java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC).minusSeconds(2);
        long run = ((Number)request.get("runId")).longValue();
        // Registration already snapshotted the scope. Attach source evidence to that snapshot.
        long tool = db.queryForObject("INSERT INTO secret_tool_runs(run_scope_id,engine,engine_version,config_hash,status)"
                + " SELECT run_scope_id,'GITLEAKS','query-fixture','query-fixture','SUCCEEDED'"
                + " FROM secret_run_scopes WHERE run_id=? AND scope_id=? RETURNING tool_run_id",
                Long.class, run, scope);
        db.update("INSERT INTO secret_findings(occurrence_id,run_id,tool_run_id,finding_key,rule_id,rule_version,detected_at)"
                + " VALUES(?,?,?,gen_random_uuid()::text,'query-fixture','1',?)", occurrence, run, tool, observationTime);
        long attempt = SecretValidationTestFixtures.completed(db, occurrence, job,
                run, "UNKNOWN", "PROVIDER_UNAVAILABLE",
                observationTime, observationTime.plusSeconds(1), observationTime);
        db.update("UPDATE secret_validation_attempts SET next_due_at=clock_timestamp()+interval '2 minutes' WHERE attempt_id=?", attempt);
        db.update("UPDATE secret_jobs SET status='FAILED',finished_at=clock_timestamp(),last_error_code='VALIDATOR_TEMPORARY' WHERE job_id=?", job);
        var terminal = service.requestStatus(job, "security");
        assertThat(terminal).containsEntry("status", "FAILED").containsEntry("nextRetryAt", null)
                .containsEntry("availableAt", null);
        var read = service.read(key, occurrence, "security");
        assertThat(read.get("nextDueAt")).isNull();
        assertThat(((Map<?,?>)read.get("latestRequest")).get("status")).isEqualTo("FAILED");
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

    private void useNotionCredential() {
        db.update("UPDATE secret_credential_sets SET issuer='NOTION',"
                + " credential_type='NOTION_CONNECTION_TOKEN' WHERE credential_set_id=?", key);
        service = new SecretValidationService(db, new SecretAccessService(db),
                new SecretCommandExecutor(db, tx), false, false, true, true, true);
    }

    private Map<String, Object> request(String idempotencyKey) {
        var read = service.read(key, occurrence, "security");
        return service.request(key, Map.of("occurrenceId", occurrence,
                "expectedContextVersion", read.get("contextVersion"),
                "idempotencyKey", idempotencyKey), "security");
    }

    private long completedNotionObservation() {
        var request = request("notion-identity");
        long run = ((Number) request.get("runId")).longValue();
        long job = ((Number) request.get("jobId")).longValue();
        var checked = java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC).minusSeconds(2);
        long tool = db.queryForObject("INSERT INTO secret_tool_runs(run_scope_id,engine,engine_version,config_hash,status)"
                + " SELECT run_scope_id,'GITLEAKS','query-fixture','query-fixture','SUCCEEDED'"
                + " FROM secret_run_scopes WHERE run_id=? AND scope_id=? RETURNING tool_run_id",
                Long.class, run, scope);
        db.update("INSERT INTO secret_findings(occurrence_id,run_id,tool_run_id,finding_key,rule_id,rule_version,detected_at)"
                + " VALUES(?,?,?,gen_random_uuid()::text,'query-fixture','1',?)", occurrence, run, tool, checked);
        long attempt = SecretValidationTestFixtures.completed(db, occurrence, job, run,
                "VALID", "AUTHENTICATED", checked, checked.plusSeconds(1), checked);
        db.update("UPDATE secret_validation_attempts SET validator_id='NOTION_GET_SELF',"
                + " endpoint_class='NOTION_SELF',http_status=200 WHERE attempt_id=?", attempt);
        db.update("UPDATE secret_jobs SET status='SUCCEEDED',finished_at=clock_timestamp() WHERE job_id=?", job);
        return attempt;
    }
}
