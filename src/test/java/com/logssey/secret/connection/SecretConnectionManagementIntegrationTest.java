package com.logssey.secret.connection;

import static com.logssey.secret.connection.SecretConnectionManagementContracts.*;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.logssey.common.error.*;
import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.command.SecretCommandExecutor;
import com.logssey.secret.connection.core.*;
import com.logssey.secret.testing.SecretTestPostgres;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;

import java.security.KeyPairGenerator;
import java.time.*;
import java.util.*;

class SecretConnectionManagementIntegrationTest {
    static final SecretTestPostgres POSTGRES = new SecretTestPostgres();
    static JdbcTemplate jdbc;
    static DriverManagerDataSource dataSource;
    static String pem;
    ConnectionCredentialStore remote;
    SourceConnectionCredentialResolver resolver;
    GitHubInstallationClient github;
    SecretConnectionManagementService service;
    Map<String, String> stored;

    @BeforeAll
    static void start() throws Exception {
        POSTGRES.start();
        dataSource =
                new DriverManagerDataSource(
                        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(dataSource).load().migrate();
        jdbc = new JdbcTemplate(dataSource);
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        pem =
                "-----"
                        + "BEGIN PRIVATE KEY-----\n"
                        + Base64.getMimeEncoder(64, new byte[] {'\n'})
                                .encodeToString(
                                        generator.generateKeyPair().getPrivate().getEncoded())
                        + "\n-----"
                        + "END PRIVATE KEY-----";
    }

    @AfterAll
    static void stop() {
        POSTGRES.stop();
    }

    @BeforeEach
    void reset() {
        jdbc.execute("TRUNCATE secret_connections,dashboard_users RESTART IDENTITY CASCADE");
        jdbc.update(
                "INSERT INTO dashboard_users(login_id,password_hash,display_name,role)"
                    + " VALUES('operator','unused','Operator','ADMIN'),('stranger','unused','Other','ADMIN')");
        jdbc.update(
                "INSERT INTO secret_role_grants(user_id,role,granted_by_user_id,grant_source)"
                    + " VALUES(1,'OPERATIONS',1,'MANUAL')");
        remote = mock(ConnectionCredentialStore.class);
        github = mock(GitHubInstallationClient.class);
        stored = new HashMap<>();
        when(remote.put(anyString(), anyString(), anyString()))
                .thenAnswer(
                        invocation -> {
                            String name = invocation.getArgument(0),
                                    version = invocation.getArgument(1);
                            stored.put(name + ":" + version, invocation.getArgument(2));
                            return new ConnectionCredentialStore.Reference(name, version);
                        });
        when(remote.get(any()))
                .thenAnswer(
                        invocation -> {
                            var ref =
                                    invocation.getArgument(
                                            0, ConnectionCredentialStore.Reference.class);
                            return stored.get(ref.secretName() + ":" + ref.versionId());
                        });
        when(remote.scheduleDeletion(anyString()))
                .thenAnswer(
                        invocation ->
                                jdbc.queryForObject(
                                                "SELECT clock_timestamp()+interval '7 days'",
                                                OffsetDateTime.class)
                                        .toInstant());
        resolver = new SourceConnectionCredentialResolver(jdbc, remote, 0, 0, "");
        var transactions = new DataSourceTransactionManager(dataSource);
        service =
                new SecretConnectionManagementService(
                        jdbc,
                        new SecretAccessService(jdbc),
                        new SecretCommandExecutor(jdbc, transactions),
                        resolver,
                        github,
                        transactions,
                        true,
                        "123456789012",
                        "ap-northeast-1",
                        "logssey/dashboard/source-credentials/");
    }

    @Test
    void storesOnlyImmutableReferencesAndReplaysCreationWithoutDuplicatingSecrets() {
        var request = new Create("GITHUB", "GitHub production", "create-once", credential());
        var first = service.create("operator", request);
        var again = service.create("operator", request);
        assertThat(again.get("connectionId")).isEqualTo(first.get("connectionId"));
        assertThat(first)
                .containsEntry("status", "PAUSED")
                .containsEntry("credentialConfigured", true);
        verify(remote, times(1)).put(anyString(), anyString(), anyString());
        String metadata =
                jdbc.queryForObject(
                        "SELECT to_jsonb(v)::text FROM secret_source_credential_versions v",
                        String.class);
        assertThat(metadata).doesNotContain(pem, "BEGIN PRIVATE KEY", "privateKey");
        assertThat(first.toString()).doesNotContain(pem, "secret_name", "secret_version_id");
        assertThat(
                        jdbc.queryForObject(
                                "SELECT count(*) FROM secret_audit_events WHERE"
                                    + " event_type='SOURCE_CONNECTION_CREATED'",
                                Long.class))
                .isEqualTo(1);
        assertThatThrownBy(
                        () ->
                                service.create(
                                        "operator",
                                        new Create(
                                                "GITHUB", "Changed", "create-once", credential())))
                .isInstanceOf(ApiException.class);
    }

    @Test
    void canonicalPayloadHasDeterministicOrderAndWriteOnlyRequestSerialization() {
        var value = new GitHubSourceCredential(100, 200, pem);
        String payload = value.secretPayload();
        assertThat(payload).startsWith("{\"appId\":100,\"installationId\":200,\"privateKey\":");
        assertThat(GitHubSourceCredential.fromPayload(payload).secretPayload()).isEqualTo(payload);
        String safe = new tools.jackson.databind.json.JsonMapper().writeValueAsString(credential());
        assertThat(safe).doesNotContain("privateKey", "BEGIN", pem);
        assertThat(credential().toString()).isEqualTo("GitHubCredential[redacted]");
    }

    @Test
    void rootScopeWorksThroughSettingsCoverageAndExistingGovernanceConsumers() {
        long id =
                id(
                        service.create(
                                "operator",
                                new Create("GITHUB", "Whole repository", "root", credential())));
        var changed =
                service.targets(
                        "operator",
                        id,
                        new TargetsChange(
                                1L,
                                List.of(
                                        new GitHubTarget(
                                                "Logssey/service-design-docs",
                                                "feature/security",
                                                "")),
                                List.of()));
        assertThat(changed).containsEntry("status", "PAUSED").containsEntry("scopeVersion", 2L);
        String reference =
                jdbc.queryForObject(
                        "SELECT approved_ref FROM secret_connection_scopes", String.class);
        assertThat(reference).isEqualTo("github://Logssey/service-design-docs/feature%2Fsecurity/");
        assertThat(
                        com.logssey.secret.response.SecretGithubScopePolicy.approved(
                                "GITHUB_REPOSITORY_FILES", "CURRENT_COMMIT_ONLY", reference))
                .isTrue();
        assertThat(service.change("operator", id, new SettingsChange(2L, null, "ACTIVE", null)))
                .containsEntry("status", "ACTIVE");
        var coverage = new SecretCoverageService(jdbc, new SecretAccessService(jdbc));
        var result =
                (List<Map<String, Object>>)
                        coverage.connections("operator", "ALL", "ALL", 0, 20).get("items");
        assertThat(result.getFirst().get("safeDisplayAlias")).isEqualTo("Whole repository");
        assertThat(((Map<?, ?>) result.getFirst().get("capabilities")).get("canRun"))
                .isEqualTo(true);
        assertThat(resolver.resolve(id, 3L).appId()).isEqualTo(100);
        assertThatThrownBy(() -> resolver.resolve(id, 2L))
                .hasMessage("SOURCE_CONNECTION_CREDENTIAL_UNAVAILABLE");
    }

    @Test
    void awsTargetsUseConfiguredAccountAndPreserveExistingContentScopes() {
        long id = id(service.create("operator", new Create("AWS", "Cloud metadata", "aws", null)));
        jdbc.update(
                "INSERT INTO"
                    + " secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,history_limit,enabled)"
                    + " VALUES(?,'content',1,'AWS_S3_OBJECT_CONTENT','aws://123456789012/ap-northeast-1/s3/object/private-fixture/object.txt','CURRENT_VALUE_ONLY',true)",
                id);
        var result =
                service.targets(
                        "operator",
                        id,
                        new TargetsChange(
                                1L,
                                List.of(),
                                List.of(
                                        new AwsTarget("IAM_ACCESS_KEY_METADATA", "global"),
                                        new AwsTarget(
                                                "AWS_SECRETS_MANAGER_METADATA",
                                                "ap-northeast-1"))));
        assertThat(((List<?>) result.get("awsTargets"))).hasSize(2);
        assertThat(
                        jdbc.queryForObject(
                                "SELECT enabled FROM secret_connection_scopes WHERE"
                                    + " scope_key='content'",
                                Boolean.class))
                .isTrue();
        assertThatThrownBy(
                        () ->
                                service.targets(
                                        "operator",
                                        id,
                                        new TargetsChange(
                                                2L,
                                                List.of(),
                                                List.of(
                                                        new AwsTarget(
                                                                "AWS_SECRETS_MANAGER_METADATA",
                                                                "ap-northeast-2")))))
                .isInstanceOf(ApiException.class);
        verifyNoInteractions(remote);
    }

    @Test
    void differentBranchesShareOneConnectionWhileSameBranchOverlapsAreRejected() {
        long id =
                id(
                        service.create(
                                "operator",
                                new Create("GITHUB", "Overlap", "overlap", credential())));
        service.targets(
                                        "operator",
                                        id,
                                        new TargetsChange(
                                                1L,
                                                List.of(
                                                        new GitHubTarget(
                                                                "Logssey/project", "main", ""),
                                                        new GitHubTarget(
                                                                "Logssey/project",
                                                                "feature/secret",
                                                                "config/")),
                                                List.of()));
        assertThat(
                        jdbc.queryForObject(
                                "SELECT count(*) FROM secret_connection_scopes WHERE"
                                    + " connection_id=?",
                                Long.class,
                                id))
                .isEqualTo(2);
        assertThatThrownBy(() -> service.targets("operator",id,new TargetsChange(2L,
                List.of(new GitHubTarget("Logssey/project","main",""),
                        new GitHubTarget("logssey/PROJECT","main","config/")),List.of())))
                .isInstanceOf(ApiException.class);
        service.targets("operator",id,new TargetsChange(2L,
                List.of(new GitHubTarget("Logssey/project","main",""),
                        new GitHubTarget("Logssey/project","Main","")),List.of()));
    }

    @Test
    void encodedReferenceLimitRejectsInputBeforeSqlAndLongLabelsAreSafelyTruncated() {
        long id =
                id(
                        service.create(
                                "operator",
                                new Create(
                                        "GITHUB",
                                        "Unicode paths",
                                        "unicode-boundary",
                                        credential())));
        assertThatThrownBy(
                        () ->
                                service.targets(
                                        "operator",
                                        id,
                                        new TargetsChange(
                                                1L,
                                                List.of(
                                                        new GitHubTarget(
                                                                "Logssey/project",
                                                                "main",
                                                                "한".repeat(100))),
                                                List.of())))
                .isInstanceOfSatisfying(
                        ApiException.class,
                        failure ->
                                assertThat(failure.errorCode()).isEqualTo(ErrorCode.INVALID_INPUT));
        assertThat(
                        jdbc.queryForObject(
                                "SELECT scope_version FROM secret_connections WHERE"
                                    + " connection_id=?",
                                Long.class,
                                id))
                .isEqualTo(1);
        service.targets(
                "operator",
                id,
                new TargetsChange(
                        1L,
                        List.of(
                                new GitHubTarget(
                                        "Logssey/project", "main", "folder-" + "a".repeat(225))),
                        List.of()));
        assertThat(
                        jdbc.queryForObject(
                                "SELECT length(safe_display_alias) FROM secret_connection_scopes",
                                Integer.class))
                .isEqualTo(80);
    }

    @Test
    void configurationChangeTerminatesLeasedRunScopesAndStageFactsWithCausalReason() {
        long id =
                id(
                        service.create(
                                "operator",
                                new Create("GITHUB", "Cancellation", "cancel-run", credential())));
        service.targets(
                "operator",
                id,
                new TargetsChange(
                        1L, List.of(new GitHubTarget("Logssey/project", "main", "")), List.of()));
        service.change("operator", id, new SettingsChange(2L, null, "ACTIVE", null));
        long job =
                jdbc.queryForObject(
                        """
                        INSERT INTO secret_jobs(kind,purpose,connection_id,scheduled_at,available_at,attempt_no,max_attempts,status,
                          lease_owner,lease_until,lease_token,lease_generation)
                        VALUES('FULL_SCAN','COLLECTION_AND_DETECTION',?,clock_timestamp(),clock_timestamp(),1,3,'LEASED','worker',clock_timestamp()+interval '5 minutes',gen_random_uuid(),1)
                        RETURNING job_id
                        """,
                        Long.class,
                        id);
        long run =
                jdbc.queryForObject(
                        """
                        INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,
                          collection_status,detection_status,validation_status,result_status)
                        VALUES(?,?,'MANUAL',3,clock_timestamp(),clock_timestamp(),'SUCCEEDED','RUNNING','PENDING','RUNNING') RETURNING run_id
                        """,
                        Long.class,
                        job,
                        id);
        jdbc.update(
                """
                INSERT INTO secret_run_scopes(run_id,scope_id,collection_status,detection_stage_status,validation_stage_status,object_count)
                SELECT ?,scope_id,'SUCCEEDED','RUNNING','PENDING',1 FROM secret_connection_scopes WHERE connection_id=? AND enabled
                """,
                run,
                id);
        jdbc.queryForObject(
                "SELECT"
                    + " secret_append_execution_event(?,NULL,1,1,'DETECTION','STAGE_SUMMARY','STARTED',NULL,NULL,NULL,NULL,NULL,'detect-start',true)",
                Boolean.class,
                run);
        service.change("operator", id, new SettingsChange(3L, null, "PAUSED", null));
        assertThat(
                        jdbc.queryForMap(
                                "SELECT status,lease_token,last_error_code FROM secret_jobs WHERE"
                                    + " job_id=?",
                                job))
                .containsEntry("status", "CANCELLED")
                .containsEntry("lease_token", null)
                .containsEntry("last_error_code", "SOURCE_CONFIGURATION_CHANGED");
        assertThat(
                        jdbc.queryForMap(
                                "SELECT"
                                    + " collection_status,detection_status,validation_status,result_status,failure_code"
                                    + " FROM secret_scan_runs WHERE run_id=?",
                                run))
                .containsEntry("collection_status", "SUCCEEDED")
                .containsEntry("detection_status", "FAILED")
                .containsEntry("validation_status", "SKIPPED")
                .containsEntry("result_status", "FAILED")
                .containsEntry("failure_code", "SOURCE_CONFIGURATION_CHANGED");
        assertThat(
                        jdbc.queryForMap(
                                "SELECT"
                                    + " detection_stage_status,validation_stage_status,validation_reason_code"
                                    + " FROM secret_run_scopes WHERE run_id=?",
                                run))
                .containsEntry("detection_stage_status", "FAILED")
                .containsEntry("validation_stage_status", "SKIPPED")
                .containsEntry("validation_reason_code", "SOURCE_CONFIGURATION_CHANGED");
        assertThat(
                        jdbc.queryForObject(
                                "SELECT count(*) FROM secret_run_execution_stage_facts WHERE"
                                    + " run_id=? AND attempt_no=1 AND finished_at IS NULL",
                                Long.class,
                                run))
                .isZero();
        assertThat(
                        jdbc.queryForObject(
                                "SELECT count(*) FROM secret_run_execution_events WHERE run_id=?"
                                    + " AND reason_code='SOURCE_CONFIGURATION_CHANGED'",
                                Long.class,
                                run))
                .isGreaterThanOrEqualTo(4);
        assertThatThrownBy(() -> resolver.resolve(id, 3L))
                .hasMessage("SOURCE_CONNECTION_CREDENTIAL_UNAVAILABLE");
    }

    @Test
    void renamingPreservesScopeVersionScheduleAndPendingWork() {
        long id = id(service.create("operator", new Create("AWS", "Account", "rename", null)));
        jdbc.update("UPDATE secret_connections SET status='ACTIVE',next_due_at=clock_timestamp()+interval '1 hour' WHERE connection_id=?",id);
        var due=jdbc.queryForObject("SELECT next_due_at FROM secret_connections WHERE connection_id=?",OffsetDateTime.class,id);
        long job=jdbc.queryForObject("INSERT INTO secret_jobs(kind,connection_id,requested_by_user_id,scheduled_at,available_at,attempt_no,max_attempts,status) "
                + "VALUES('FULL_SCAN',?,1,now(),now(),0,3,'PENDING') RETURNING job_id",Long.class,id);
        var result=service.change("operator",id,new SettingsChange(1L,"Renamed",null,null,1L));
        assertThat(result).containsEntry("scopeVersion",1L).containsEntry("settingsVersion",2L);
        assertThat(jdbc.queryForObject("SELECT status FROM secret_jobs WHERE job_id=?",String.class,job)).isEqualTo("PENDING");
        assertThat(jdbc.queryForObject("SELECT next_due_at FROM secret_connections WHERE connection_id=?",OffsetDateTime.class,id)).isEqualTo(due);
        assertThatThrownBy(() -> service.change("operator",id,new SettingsChange(1L,"Stale",null,null,1L))).isInstanceOf(ApiException.class);
    }

    @Test
    void targetSaveCanActivateAndUnknownWorkerCapabilitiesRemainExplicit() {
        long id=id(service.create("operator",new Create("AWS","Account","activate",null)));
        var result=service.targets("operator",id,new TargetsChange(1L,List.of(),
                List.of(new AwsTarget("IAM_ACCESS_KEY_METADATA","global")),true,1L));
        assertThat(result).containsEntry("status","ACTIVE");
        assertThat(((Map<?,?>)result.get("validationReadiness")).get("ready")).isEqualTo(false);
        assertThat((List<String>)((Map<?,?>)result.get("validationReadiness")).get("reasonCodes")).contains("WORKER_CAPABILITIES_UNKNOWN");
    }

    @Test
    void requiresLiveOperationsRoleAndOptimisticVersionForEveryMutation() {
        long id = id(service.create("operator", new Create("AWS", "Account", "roles", null)));
        assertThatThrownBy(() -> service.settings("stranger", id)).isInstanceOf(ApiException.class);
        assertThatThrownBy(
                        () -> service.create("stranger", new Create("AWS", "Other", "other", null)))
                .isInstanceOf(ApiException.class);
        service.change("operator", id, new SettingsChange(1L, "Renamed", null, null, 1L));
        assertThatThrownBy(
                        () ->
                                service.change(
                                        "operator",
                                        id,
                                        new SettingsChange(1L, "Stale", null, null, 1L)))
                .isInstanceOf(ApiException.class);
        jdbc.update("UPDATE secret_role_grants SET revoked_at=clock_timestamp() WHERE user_id=1");
        assertThatThrownBy(() -> service.settings("operator", id)).isInstanceOf(ApiException.class);
        assertThatThrownBy(
                        () ->
                                service.create(
                                        "operator", new Create("AWS", "Account", "roles", null)))
                .isInstanceOf(ApiException.class);
    }

    @Test
    void unchangedLegacyRegionalTargetKeepsItsOriginalReference() {
        long id =
                id(
                        service.create(
                                "operator",
                                new Create("AWS", "Existing region", "existing-region", null)));
        jdbc.update(
                "INSERT INTO"
                    + " secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,history_limit,enabled)"
                    + " VALUES(?,'old-region',1,'AWS_SECRETS_MANAGER_METADATA','aws://123456789012/ap-northeast-2/secrets-manager/all','CURRENT_STATE_ONLY',true)",
                id);
        var result =
                service.targets(
                        "operator",
                        id,
                        new TargetsChange(
                                1L,
                                List.of(),
                                List.of(
                                        new AwsTarget(
                                                "AWS_SECRETS_MANAGER_METADATA", "ap-northeast-2"),
                                        new AwsTarget("IAM_ACCESS_KEY_METADATA", "global"))));
        assertThat((List<?>) result.get("awsTargets")).hasSize(2);
        assertThat(
                        jdbc.queryForObject(
                                "SELECT approved_ref FROM secret_connection_scopes WHERE"
                                    + " scope_key='old-region' AND enabled",
                                String.class))
                .isEqualTo("aws://123456789012/ap-northeast-2/secrets-manager/all");
    }

    @Test
    void rotationKeepsOldVersionAndDeletionSchedulesSevenDayRecovery() {
        long id =
                id(
                        service.create(
                                "operator",
                                new Create("GITHUB", "Rotate", "rotation", credential())));
        var next =
                service.change(
                        "operator",
                        id,
                        new SettingsChange(1L, null, null, new GitHubCredential(101L, 201L, pem)));
        assertThat(next).containsEntry("credentialVersion", 2L).containsEntry("status", "PAUSED");
        assertThat(
                        jdbc.queryForObject(
                                "SELECT count(*) FROM secret_source_credential_versions",
                                Long.class))
                .isEqualTo(2);
        assertThat(resolver.resolve(id).appId()).isEqualTo(101);
        var deleted = service.disableCredential("operator", id, 2L);
        assertThat(deleted)
                .containsEntry("credentialConfigured", false)
                .containsEntry("credentialDeletionPending", true)
                .containsEntry("canRestoreCredential", true);
        assertThatThrownBy(() -> resolver.resolve(id))
                .hasMessage("SOURCE_CONNECTION_CREDENTIAL_UNAVAILABLE");
        verify(remote).scheduleDeletion(anyString());
        var restored = service.restoreCredential("operator", id, 3L);
        assertThat(restored)
                .containsEntry("credentialConfigured", true)
                .containsEntry("credentialDeletionPending", false)
                .containsEntry("status", "PAUSED");
        assertThat(resolver.resolve(id).appId()).isEqualTo(101);
        verify(remote).restore(anyString());
    }

    @Test
    void failedDatabaseCommitRestoresRemoteDeletionAndPreservesCurrentReference() {
        long id =
                id(
                        service.create(
                                "operator",
                                new Create(
                                        "GITHUB", "Compensation", "compensation", credential())));
        jdbc.execute(
                "CREATE FUNCTION reject_test_disable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN"
                    + " IF OLD.source_credential_enabled AND NOT NEW.source_credential_enabled THEN"
                    + " RAISE EXCEPTION 'TEST_REJECT'; END IF; RETURN NEW; END $$");
        jdbc.execute(
                "CREATE TRIGGER reject_test_disable BEFORE UPDATE ON secret_connections FOR EACH"
                    + " ROW EXECUTE FUNCTION reject_test_disable()");
        try {
            assertThatThrownBy(() -> service.disableCredential("operator", id, 1L))
                    .isInstanceOf(RuntimeException.class);
            verify(remote).scheduleDeletion(anyString());
            verify(remote).restore(anyString());
            assertThat(service.settings("operator", id))
                    .containsEntry("credentialConfigured", true)
                    .containsEntry("credentialDeletionPending", false)
                    .containsEntry("scopeVersion", 1L);
        } finally {
            jdbc.execute("DROP TRIGGER reject_test_disable ON secret_connections");
            jdbc.execute("DROP FUNCTION reject_test_disable()");
        }
    }

    @Test
    void failedRemoteCompensationLeavesConnectionPausedAndRecoverable() {
        long id =
                id(
                        service.create(
                                "operator",
                                new Create("GITHUB", "Recovery", "recovery", credential())));
        doThrow(new IllegalStateException("synthetic remote failure"))
                .when(remote)
                .restore(anyString());
        jdbc.execute("CREATE SEQUENCE reject_once_sequence");
        jdbc.execute(
                "CREATE FUNCTION reject_once_disable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN"
                    + " IF OLD.source_credential_enabled AND NOT NEW.source_credential_enabled AND"
                    + " nextval('reject_once_sequence')=1 THEN RAISE EXCEPTION 'TEST_REJECT_ONCE';"
                    + " END IF; RETURN NEW; END $$");
        jdbc.execute(
                "CREATE TRIGGER reject_once_disable BEFORE UPDATE ON secret_connections FOR EACH"
                    + " ROW EXECUTE FUNCTION reject_once_disable()");
        try {
            assertThatThrownBy(() -> service.disableCredential("operator", id, 1L))
                    .isInstanceOf(RuntimeException.class);
            assertThat(service.settings("operator", id))
                    .containsEntry("status", "PAUSED")
                    .containsEntry("credentialConfigured", false)
                    .containsEntry("credentialDeletionPending", true)
                    .containsEntry("canRestoreCredential", true);
        } finally {
            jdbc.execute("DROP TRIGGER reject_once_disable ON secret_connections");
            jdbc.execute("DROP FUNCTION reject_once_disable()");
            jdbc.execute("DROP SEQUENCE reject_once_sequence");
        }
    }

    @Test
    void individualConnectionsResolveTheirOwnPinnedCredentialVersion() {
        long first =
                id(
                        service.create(
                                "operator", new Create("GITHUB", "First", "first", credential())));
        long second =
                id(
                        service.create(
                                "operator",
                                new Create(
                                        "GITHUB",
                                        "Second",
                                        "second",
                                        new GitHubCredential(102L, 202L, pem))));
        assertThat(resolver.resolve(first).appId()).isEqualTo(100);
        assertThat(resolver.resolve(second).appId()).isEqualTo(102);
        assertThat(
                        jdbc.queryForObject(
                                "SELECT count(DISTINCT secret_name) FROM"
                                    + " secret_source_credential_versions",
                                Long.class))
                .isEqualTo(2);
    }

    @Test
    void expiredDeletionAllowsFreshCredentialsOnTheSameConnectionAndNewSecretName() {
        long id =
                id(
                        service.create(
                                "operator",
                                new Create("GITHUB", "Expired", "expired", credential())));
        String oldName =
                jdbc.queryForObject(
                        "SELECT secret_name FROM secret_source_credential_versions WHERE"
                            + " connection_id=? AND version=1",
                        String.class,
                        id);
        service.disableCredential("operator", id, 1L);
        jdbc.update(
                "UPDATE secret_connections SET credential_recovery_until=clock_timestamp()-interval"
                    + " '1 second' WHERE connection_id=?",
                id);
        assertThat(service.settings("operator", id))
                .containsEntry("credentialDeletionPending", false)
                .containsEntry("canRestoreCredential", false)
                .containsEntry("credentialConfigured", false);
        var replaced =
                service.change(
                        "operator",
                        id,
                        new SettingsChange(2L, null, null, new GitHubCredential(103L, 203L, pem)));
        assertThat(replaced)
                .containsEntry("connectionId", id)
                .containsEntry("credentialVersion", 2L)
                .containsEntry("credentialConfigured", true)
                .containsEntry("status", "PAUSED");
        assertThat(
                        jdbc.queryForObject(
                                "SELECT secret_name FROM secret_source_credential_versions WHERE"
                                    + " connection_id=? AND version=2",
                                String.class,
                                id))
                .isNotEqualTo(oldName)
                .endsWith("-v2");
        assertThat(resolver.resolve(id).appId()).isEqualTo(103);
        assertThat(
                        jdbc.queryForObject(
                                "SELECT count(*) FROM secret_source_credential_versions WHERE"
                                    + " connection_id=?",
                                Long.class,
                                id))
                .isEqualTo(2);
    }

    @Test
    void providerFailureNeverEchoesSecretMaterialAndRollsBackCreation() {
        when(remote.put(anyString(), anyString(), anyString()))
                .thenThrow(new IllegalStateException(pem));
        assertThatThrownBy(
                        () ->
                                service.create(
                                        "operator",
                                        new Create("GITHUB", "Failure", "failure", credential())))
                .isInstanceOf(ApiException.class)
                .hasMessageNotContaining("BEGIN PRIVATE KEY")
                .hasNoCause();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_connections", Long.class))
                .isZero();
        assertThatThrownBy(
                        () ->
                                service.create(
                                        "operator",
                                        new Create(
                                                "GITHUB",
                                                "Invalid",
                                                "invalid",
                                                new GitHubCredential(
                                                        100L, 200L, "private-synthetic-invalid"))))
                .isInstanceOf(ApiException.class)
                .hasNoCause();
    }

    @Test
    void malformedCredentialHttpResponseAndApplicationLogsContainNoSubmittedMaterial()
            throws Exception {
        var logger =
                (ch.qos.logback.classic.Logger)
                        org.slf4j.LoggerFactory.getLogger(GlobalExceptionHandler.class);
        var events =
                new ch.qos.logback.core.read.ListAppender<
                        ch.qos.logback.classic.spi.ILoggingEvent>();
        events.start();
        logger.addAppender(events);
        try {
            var mvc =
                    org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup(
                                    new SecretConnectionManagementController(service))
                            .setControllerAdvice(new GlobalExceptionHandler())
                            .build();
            String submitted = "private-synthetic-invalid-material";
            String body =
                    new tools.jackson.databind.json.JsonMapper()
                            .writeValueAsString(
                                    Map.of(
                                            "provider",
                                            "GITHUB",
                                            "displayName",
                                            "Invalid",
                                            "idempotencyKey",
                                            "http-invalid",
                                            "githubCredential",
                                            Map.of(
                                                    "appId",
                                                    100,
                                                    "installationId",
                                                    200,
                                                    "privateKey",
                                                    submitted)));
            mvc.perform(
                            org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                                    .post("/api/v1/secrets/connections")
                                    .principal(
                                            new org.springframework.security.authentication
                                                    .UsernamePasswordAuthenticationToken(
                                                    "operator", "unused"))
                                    .contentType(
                                            org.springframework.http.MediaType.APPLICATION_JSON)
                                    .content(body))
                    .andExpect(
                            org.springframework.test.web.servlet.result.MockMvcResultMatchers
                                    .status()
                                    .isBadRequest())
                    .andExpect(
                            org.springframework.test.web.servlet.result.MockMvcResultMatchers
                                    .content()
                                    .string(
                                            org.hamcrest.Matchers.not(
                                                    org.hamcrest.Matchers.containsString(
                                                            submitted))));
            assertThat(events.list).isEmpty();
        } finally {
            logger.detachAppender(events);
            events.stop();
        }
    }

    @Test void newlyRegisteredTargetsReturnOnePinnedPolicySetupSummary() {
        long connection=id(service.create("operator",new Create("GITHUB","Pinned target policy","pin-create",credential())));
        service.targets("operator",connection,new TargetsChange(1L,List.of(new GitHubTarget("Logssey/service-design-docs","main","")),List.of()));
        long scope=jdbc.queryForObject("SELECT scope_id FROM secret_connection_scopes WHERE connection_id=?",Long.class,connection);
        long policy=jdbc.queryForObject("""
            INSERT INTO secret_storage_policies(version,status,reason_code,evidence_ref,created_by_user_id,
              approved_by_user_id,approved_at,valid_from)
            VALUES(1,'ACTIVE','AUTHORIZED_STORAGE','TICKET:SEC-1',1,2,now(),now()-interval '1 hour') RETURNING policy_id
            """,Long.class);
        jdbc.update("""
            INSERT INTO secret_storage_policy_rules(policy_id,policy_version,effect,connection_id,scope_id,
              scope_revision,scope_fingerprint,content_type,path_match)
            SELECT ?,1,'ALLOW',connection_id,scope_id,revision,
              md5(jsonb_build_array(content_type,approved_ref,history_limit)::text),content_type,'SCOPE'
            FROM secret_connection_scopes WHERE scope_id=?
            """,policy,scope);
        jdbc.update("INSERT INTO secret_connection_policy_defaults(connection_id,policy_id,policy_version,selected_by_user_id) VALUES(?,?,1,1)",connection,policy);
        var changed=service.targets("operator",connection,new TargetsChange(2L,List.of(
            new GitHubTarget("Logssey/service-design-docs","main",""),new GitHubTarget("Logssey/dashboard-backend","main","")),List.of()));
        var summary=(Map<String,Object>)changed.get("defaultStoragePolicy");
        assertThat(summary).containsEntry("selectedPolicyId",policy).containsEntry("status","RULE_UPDATE_REQUIRED")
            .containsEntry("ruleUpdateRequiredScopeCount",1L);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_scope_policy_bindings WHERE scope_id<>?",Long.class,scope)).isZero();
    }

    private GitHubCredential credential() {
        return new GitHubCredential(100L, 200L, pem);
    }

    private long id(Map<String, Object> value) {
        return ((Number) value.get("connectionId")).longValue();
    }
}
