package com.logssey.secret.run;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Optional;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecretRunServiceTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static JdbcTemplate jdbc;
    private static DataSourceTransactionManager transactions;
    private SecretRunService service;

    @BeforeAll
    static void startDatabase() {
        POSTGRES.start();
        var datasource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(datasource).load().migrate();
        jdbc = new JdbcTemplate(datasource);
        transactions = new DataSourceTransactionManager(datasource);
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @BeforeEach
    void reset() {
        jdbc.execute("TRUNCATE secret_connections, dashboard_users RESTART IDENTITY CASCADE");
        jdbc.update("""
                INSERT INTO dashboard_users (login_id, password_hash, display_name, role)
                VALUES ('admin', 'test-hash', 'Test Admin', 'ADMIN')
                """);
        service = new SecretRunService(new SecretRunRepository(jdbc), transactions);
    }

    @Test
    void registersOnlyApprovedScopeSnapshotWithoutAdvancingScheduleOrScanning() {
        var originalDue = OffsetDateTime.now(ZoneOffset.UTC).minusHours(2).truncatedTo(ChronoUnit.MICROS);
        long connection = connection("ACTIVE", originalDue);
        long approved = scope(connection, "fixtures/", true);
        scope(connection, "unapproved/", false);

        var response = service.register(new SecretRunRequest(connection, null), "admin");

        assertThat(response.status()).isEqualTo("PENDING");
        assertThat(count("secret_jobs")).isEqualTo(1);
        assertThat(count("secret_scan_runs")).isEqualTo(1);
        assertThat(count("secret_run_scopes")).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT scope_id FROM secret_run_scopes", Long.class)).isEqualTo(approved);
        assertThat(jdbc.queryForMap("""
                SELECT kind, status, requested_by_user_id, attempt_no FROM secret_jobs
                """))
                .containsEntry("kind", "FULL_SCAN").containsEntry("status", "PENDING")
                .containsEntry("requested_by_user_id", 1L).containsEntry("attempt_no", 0);
        assertThat(jdbc.queryForMap("""
                SELECT trigger_type, scope_version, collection_status, result_status, started_at
                FROM secret_scan_runs
                """))
                .containsEntry("trigger_type", "MANUAL").containsEntry("scope_version", 1L)
                .containsEntry("collection_status", "PENDING").containsEntry("result_status", "PENDING")
                .containsEntry("started_at", null);
        assertThat(jdbc.queryForObject("SELECT next_due_at FROM secret_connections", OffsetDateTime.class))
                .isEqualTo(originalDue);
        assertThat(service.status(response.runId(), "admin").scopeCount()).isEqualTo(1);

        jdbc.update("UPDATE secret_connection_scopes SET enabled = false WHERE scope_id = ?", approved);
        assertThat(service.status(response.runId(), "admin").scopeCount()).isEqualTo(1);
    }

    @Test
    void idempotentReplayReturnsTheOriginalRunAndDoesNotStoreRawKey() {
        long first = connection("ACTIVE", null);
        long second = connection("ACTIVE", null);
        scope(first, "one/", true);
        scope(second, "two/", true);

        var request = new SecretRunRequest(first, "request-123");
        var accepted = service.register(request, "admin");
        assertThat(service.register(request, "admin")).isEqualTo(accepted);
        assertThat(jdbc.queryForObject("SELECT idempotency_key FROM secret_jobs", String.class))
                .startsWith("manual:").doesNotContain("request-123");
        assertThat(count("secret_jobs")).isEqualTo(1);

        assertConflict(() -> service.register(new SecretRunRequest(second, "request-123"), "admin"));
        assertConflict(() -> service.register(new SecretRunRequest(first, "different-key"), "admin"));
        assertThat(service.register(new SecretRunRequest(first, null), "admin").runId())
                .isEqualTo(accepted.runId());
        assertThat(count("secret_jobs")).isEqualTo(1);
    }

    @Test
    void completedRunCanBeReplayedByItsKeyWhileASecondRequestCreatesANewRun() {
        long connection = connection("ACTIVE", null);
        scope(connection, "fixtures/", true);
        var old = service.register(new SecretRunRequest(connection, "old-key"), "admin");
        jdbc.update("""
                UPDATE secret_jobs SET status = 'SUCCEEDED', finished_at = CURRENT_TIMESTAMP
                WHERE connection_id = ?
                """, connection);
        jdbc.update("""
                UPDATE secret_scan_runs SET result_status = 'SUCCEEDED', finished_at = CURRENT_TIMESTAMP
                WHERE run_id = ?
                """, old.runId());

        assertThat(service.register(new SecretRunRequest(connection, "old-key"), "admin"))
                .isEqualTo(new SecretRunAcceptedResponse(old.runId(), "SUCCEEDED"));
        var next = service.register(new SecretRunRequest(connection, "new-key"), "admin");
        assertThat(next.runId()).isNotEqualTo(old.runId());
        assertThat(count("secret_jobs")).isEqualTo(2);
    }

    @Test
    void idempotencyReplayDoesNotReturnAnOldJobAfterProviderBecomesUnsupported() {
        long connection = connection("ACTIVE", null);
        scope(connection, "fixtures/", true);
        var request = new SecretRunRequest(connection, "previous-github-run");
        service.register(request, "admin");
        jdbc.update("UPDATE secret_connections SET provider = 'AWS' WHERE connection_id = ?", connection);

        assertConflict(() -> service.register(request, "admin"));
        assertThat(count("secret_jobs")).isEqualTo(1);
    }

    @Test
    void rejectsUnknownInactiveAndUnapprovedConnectionsWithoutPartialWrites() {
        long paused = connection("PAUSED", null);
        scope(paused, "paused/", true);
        long noScopes = connection("ACTIVE", null);
        scope(noScopes, "disabled/", false);
        long unsupported = connection("AWS", "ACTIVE", null);
        scope(unsupported, "fixtures/", true);

        assertCode(ErrorCode.NOT_FOUND, () -> service.register(new SecretRunRequest(999L, null), "admin"));
        assertConflict(() -> service.register(new SecretRunRequest(paused, null), "admin"));
        assertConflict(() -> service.register(new SecretRunRequest(noScopes, null), "admin"));
        assertConflict(() -> service.register(new SecretRunRequest(unsupported, null), "admin"));
        assertThat(count("secret_jobs")).isZero();
        assertThat(count("secret_scan_runs")).isZero();
        assertThat(count("secret_run_scopes")).isZero();
    }

    @Test
    void registersAwsOnlyWhenEveryEnabledScopeIsSupportedIamMetadata() {
        long iamOnly = connection("AWS", "ACTIVE", null);
        jdbc.update("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref,
                     history_limit, enabled)
                VALUES (?, 'iam-keys', 1, 'IAM_ACCESS_KEY_METADATA',
                        'aws://123456789012/global/iam/access-keys', 'CURRENT_STATE_ONLY', true)
                """, iamOnly);
        var accepted = service.register(new SecretRunRequest(iamOnly, null), "admin");
        assertThat(accepted.status()).isEqualTo("PENDING");
        assertThat(service.status(accepted.runId(), "admin").scopeCount()).isEqualTo(1);

        long mixed = connection("AWS", "ACTIVE", null);
        jdbc.update("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref,
                     history_limit, enabled)
                VALUES (?, 'iam-keys', 1, 'IAM_ACCESS_KEY_METADATA',
                        'aws://123456789012/global/iam/access-keys', 'CURRENT_STATE_ONLY', true),
                       (?, 'other', 1, 'AWS_SECRET_VALUE', 'aws://123456789012/other',
                        'CURRENT_VALUE_ONLY', true)
                """, mixed, mixed);
        assertConflict(() -> service.register(new SecretRunRequest(mixed, null), "admin"));
        long wrongRef = connection("AWS", "ACTIVE", null);
        jdbc.update("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref,
                     history_limit, enabled)
                VALUES (?, 'iam-keys', 1, 'IAM_ACCESS_KEY_METADATA',
                        'aws://123456789012/global/iam/users', 'CURRENT_STATE_ONLY', true)
                """, wrongRef);
        assertConflict(() -> service.register(new SecretRunRequest(wrongRef, null), "admin"));
        long wrongHistory = connection("AWS", "ACTIVE", null);
        jdbc.update("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref,
                     history_limit, enabled)
                VALUES (?, 'iam-keys', 1, 'IAM_ACCESS_KEY_METADATA',
                        'aws://123456789012/global/iam/access-keys', 'ALL_HISTORY', true)
                """, wrongHistory);
        assertConflict(() -> service.register(new SecretRunRequest(wrongHistory, null), "admin"));
        assertThat(count("secret_jobs")).isEqualTo(1);
    }

    @Test
    void acceptsMixedAwsMetadataAndReturnsSafePerScopeCoverage() {
        long connection = connection("AWS", "ACTIVE", null);
        jdbc.update("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref,
                     history_limit, enabled)
                VALUES (?, 'iam', 1, 'IAM_ACCESS_KEY_METADATA',
                        'aws://123456789012/global/iam/access-keys', 'CURRENT_STATE_ONLY', true),
                       (?, 'secrets', 1, 'AWS_SECRETS_MANAGER_METADATA',
                        'aws://123456789012/ap-northeast-2/secrets-manager/all', 'CURRENT_STATE_ONLY', true),
                       (?, 'parameters', 1, 'AWS_SSM_PARAMETER_METADATA',
                        'aws://123456789012/us-east-1/ssm/parameters', 'CURRENT_STATE_ONLY', true),
                       (?, 'buckets', 1, 'AWS_S3_BUCKET_METADATA',
                        'aws://123456789012/global/s3/buckets', 'CURRENT_STATE_ONLY', true)
                """, connection, connection, connection, connection);
        var accepted = service.register(new SecretRunRequest(connection, null), "admin");
        assertThat(service.status(accepted.runId(), "admin").scopeCount()).isEqualTo(4);
        jdbc.update("""
                UPDATE secret_run_scopes rs SET collection_status = 'SUCCEEDED', object_count = 2,
                    finished_at = CURRENT_TIMESTAMP
                FROM secret_connection_scopes s
                WHERE rs.scope_id = s.scope_id AND rs.run_id = ?
                  AND s.content_type = 'AWS_SECRETS_MANAGER_METADATA'
                """, accepted.runId());
        jdbc.update("""
                UPDATE secret_run_scopes rs SET collection_status = 'PARTIAL', object_count = 1,
                    failure_code = 'AWS_ACCESS_DENIED', finished_at = CURRENT_TIMESTAMP
                FROM secret_connection_scopes s
                WHERE rs.scope_id = s.scope_id AND rs.run_id = ?
                  AND s.content_type = 'AWS_SSM_PARAMETER_METADATA'
                """, accepted.runId());
        var status = service.status(accepted.runId(), "admin");
        assertThat(status.scopeResults()).hasSize(4);
        assertThat(status.scopeResults()).filteredOn(item ->
                "AWS_SECRETS_MANAGER_METADATA".equals(item.contentType()))
                .singleElement().satisfies(item -> {
                    assertThat(item.region()).isEqualTo("ap-northeast-2");
                    assertThat(item.objectCount()).isEqualTo(2L);
                    assertThat(item.collectionStatus()).isEqualTo("SUCCEEDED");
                });
        assertThat(status.scopeResults()).filteredOn(item ->
                "AWS_SSM_PARAMETER_METADATA".equals(item.contentType()))
                .singleElement().satisfies(item -> {
                    assertThat(item.region()).isEqualTo("us-east-1");
                    assertThat(item.gapCode()).isEqualTo("AWS_ACCESS_DENIED");
                });
        assertThat(status.toString()).doesNotContain("123456789012", "approvedRef", "authRef");

        jdbc.update("UPDATE secret_run_scopes SET failure_code = 'unsafe-provider-value' WHERE run_id = ?",
                accepted.runId());
        assertThat(service.status(accepted.runId(), "admin").scopeResults())
                .allSatisfy(item -> assertThat(item.gapCode()).isEqualTo("UNSPECIFIED_FAILURE"));
    }

    @Test
    void registersThreeExactAwsValueScopesAndExposesOnlyRegionAndSafeGap() {
        long connection = connection("AWS", "ACTIVE", null);
        jdbc.update("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref,
                     history_limit, enabled)
                VALUES (?, 'secret-value', 1, 'AWS_SECRETS_MANAGER_VALUE',
                        'aws://123456789012/ap-northeast-2/secrets-manager/secret/arn%3Aaws%3Asecretsmanager%3Aap-northeast-2%3A123456789012%3Asecret%3Afixture-A',
                        'CURRENT_VALUE_ONLY', true),
                       (?, 'parameter-value', 1, 'AWS_SSM_PARAMETER_VALUE',
                        'aws://123456789012/us-east-1/ssm/parameter/arn%3Aaws%3Assm%3Aus-east-1%3A123456789012%3Aparameter%2Ffixture%2Fconfig',
                        'CURRENT_VALUE_ONLY', true),
                       (?, 'object-content', 1, 'AWS_S3_OBJECT_CONTENT',
                        'aws://123456789012/eu-west-1/s3/object/fixture-bucket/config%2Fapp.yaml',
                        'CURRENT_VALUE_ONLY', true)
                """, connection, connection, connection);

        var accepted = service.register(new SecretRunRequest(connection, null), "admin");
        assertThat(accepted.status()).isEqualTo("PENDING");
        assertThat(service.status(accepted.runId(), "admin").scopeCount()).isEqualTo(3);
        jdbc.update("""
                UPDATE secret_run_scopes rs SET collection_status = 'FAILED', object_count = 0,
                    failure_code = 'AWS_CONTENT_READ_DISABLED', finished_at = CURRENT_TIMESTAMP
                FROM secret_connection_scopes s
                WHERE rs.scope_id = s.scope_id AND s.content_type = 'AWS_SECRETS_MANAGER_VALUE'
                """);
        var results = service.status(accepted.runId(), "admin").scopeResults();
        assertThat(results).extracting(SecretRunScopeResultResponse::contentType)
                .containsExactlyInAnyOrder("AWS_SECRETS_MANAGER_VALUE", "AWS_SSM_PARAMETER_VALUE",
                        "AWS_S3_OBJECT_CONTENT");
        assertThat(results).extracting(SecretRunScopeResultResponse::region)
                .containsExactlyInAnyOrder("ap-northeast-2", "us-east-1", "eu-west-1");
        assertThat(results).filteredOn(result ->
                "AWS_SECRETS_MANAGER_VALUE".equals(result.contentType()))
                .singleElement().extracting(SecretRunScopeResultResponse::gapCode)
                .isEqualTo("AWS_CONTENT_READ_DISABLED");
        assertThat(results.toString()).doesNotContain("123456789012", "fixture-A", "fixture-bucket",
                "config%2Fapp.yaml", "approvedRef");
    }

    @Test
    void rejectsBroadOrMalformedAwsValueScopeBeforeReservingJob() {
        for (var invalid : java.util.List.<String[]>of(
                new String[]{"AWS_SECRETS_MANAGER_VALUE",
                        "aws://123456789012/ap-northeast-2/secrets-manager/all"},
                new String[]{"AWS_SECRETS_MANAGER_VALUE",
                        "aws://123456789012/ap-northeast-2/secrets-manager/secret/fixture/another"},
                new String[]{"AWS_SECRETS_MANAGER_VALUE",
                        "aws://123456789012/ap-northeast-2/secrets-manager/secret/fixture?all=true"},
                new String[]{"AWS_SECRETS_MANAGER_VALUE",
                        "aws://123456789012/ap-northeast-2/secrets-manager/secret/%ZZ"},
                new String[]{"AWS_SSM_PARAMETER_VALUE",
                        "aws://123456789012/ap-northeast-2/ssm/parameters"},
                new String[]{"AWS_S3_OBJECT_CONTENT",
                        "aws://123456789012/ap-northeast-2/s3/object/fixture-bucket/"})) {
            long connection = connection("AWS", "ACTIVE", null);
            jdbc.update("""
                    INSERT INTO secret_connection_scopes
                        (connection_id, scope_key, revision, content_type, approved_ref,
                         history_limit, enabled)
                    VALUES (?, 'value', 1, ?, ?, 'CURRENT_VALUE_ONLY', true)
                    """, connection, invalid[0], invalid[1]);
            assertConflict(() -> service.register(new SecretRunRequest(connection, null), "admin"));
        }
        long wrongHistory = connection("AWS", "ACTIVE", null);
        jdbc.update("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref,
                     history_limit, enabled)
                VALUES (?, 'value', 1, 'AWS_S3_OBJECT_CONTENT',
                        'aws://123456789012/eu-west-1/s3/object/fixture-bucket/config%2Fapp.yaml',
                        'CURRENT_STATE_ONLY', true)
                """, wrongHistory);
        assertConflict(() -> service.register(new SecretRunRequest(wrongHistory, null), "admin"));
        assertThat(count("secret_jobs")).isZero();
    }

    @Test
    void approvedReferenceDatabaseColumnRejectsOverFiveHundredCharacters() {
        long connection = connection("AWS", "ACTIVE", null);
        assertThatThrownBy(() -> jdbc.update("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref,
                     history_limit, enabled)
                VALUES (?, 'oversized', 1, 'AWS_S3_OBJECT_CONTENT', ?, 'CURRENT_VALUE_ONLY', true)
                """, connection, "x".repeat(501)))
                .isInstanceOf(org.springframework.dao.DataAccessException.class);
        assertThat(count("secret_jobs")).isZero();
    }

    @Test
    void rejectsMetadataValuePathOrInvalidHistoryBeforeJobCreation() {
        long connection = connection("AWS", "ACTIVE", null);
        jdbc.update("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref,
                     history_limit, enabled)
                VALUES (?, 'secrets', 1, 'AWS_SECRETS_MANAGER_METADATA',
                        'aws://123456789012/ap-northeast-2/secrets-manager/value',
                        'CURRENT_STATE_ONLY', true)
                """, connection);
        assertConflict(() -> service.register(new SecretRunRequest(connection, null), "admin"));
        jdbc.update("""
                UPDATE secret_connection_scopes SET approved_ref =
                    'aws://123456789012/ap-northeast-2/secrets-manager/all',
                    history_limit = 'ALL_HISTORY' WHERE connection_id = ?
                """, connection);
        assertConflict(() -> service.register(new SecretRunRequest(connection, null), "admin"));
        assertThat(count("secret_jobs")).isZero();
    }

    @Test
    void requiresCurrentDatabaseAdminForRegistrationAndStatus() {
        long connection = connection("ACTIVE", null);
        scope(connection, "fixtures/", true);

        assertCode(ErrorCode.UNAUTHENTICATED,
                () -> service.register(new SecretRunRequest(connection, null), "missing"));
        assertCode(ErrorCode.UNAUTHENTICATED,
                () -> service.register(new SecretRunRequest(connection, null), null));
        var nonAdmin = new SecretRunService(new SecretRunRepository(jdbc) {
            @Override
            Optional<Actor> actor(String loginId) {
                return Optional.of(new Actor(1, "VIEWER"));
            }
        }, transactions);
        assertCode(ErrorCode.FORBIDDEN,
                () -> nonAdmin.register(new SecretRunRequest(connection, null), "viewer"));
        assertCode(ErrorCode.FORBIDDEN, () -> nonAdmin.status(1, "viewer"));
        assertThat(count("secret_jobs")).isZero();

        var accepted = service.register(new SecretRunRequest(connection, null), "admin");
        assertCode(ErrorCode.NOT_FOUND, () -> service.status(accepted.runId() + 100, "admin"));
    }

    @Test
    void reportsWorkerStateCountsAndOnlyAllowlistedFailureCodes() {
        long connection = connection("ACTIVE", null);
        scope(connection, "one/", true);
        scope(connection, "two/", true);
        var accepted = service.register(new SecretRunRequest(connection, null), "admin");
        jdbc.update("""
                UPDATE secret_jobs SET status = 'LEASED', lease_owner = 'test-lease',
                    lease_until = CURRENT_TIMESTAMP + INTERVAL '5 minutes', attempt_no = 1
                WHERE connection_id = ?
                """, connection);
        jdbc.update("""
                UPDATE secret_scan_runs SET result_status = 'RUNNING', collection_status = 'RUNNING',
                    started_at = CURRENT_TIMESTAMP WHERE run_id = ?
                """, accepted.runId());
        assertThat(service.status(accepted.runId(), "admin").status()).isEqualTo("RUNNING");

        jdbc.update("""
                UPDATE secret_run_scopes SET collection_status = 'SUCCEEDED', object_count = 3,
                    finished_at = CURRENT_TIMESTAMP
                WHERE scope_id = (SELECT MIN(scope_id) FROM secret_run_scopes WHERE run_id = ?)
                """, accepted.runId());
        jdbc.update("""
                UPDATE secret_run_scopes SET collection_status = 'FAILED', object_count = 0,
                    finished_at = CURRENT_TIMESTAMP, failure_code = 'SOURCE_UNAVAILABLE'
                WHERE scope_id = (SELECT MAX(scope_id) FROM secret_run_scopes WHERE run_id = ?)
                """, accepted.runId());
        jdbc.update("""
                UPDATE secret_jobs SET status = 'SUCCEEDED', lease_owner = NULL, lease_until = NULL,
                    finished_at = CURRENT_TIMESTAMP WHERE connection_id = ?
                """, connection);
        jdbc.update("""
                UPDATE secret_scan_runs SET collection_status = 'PARTIAL', detection_status = 'SUCCEEDED',
                    validation_status = 'SKIPPED', result_status = 'PARTIAL',
                    finished_at = CURRENT_TIMESTAMP WHERE run_id = ?
                """, accepted.runId());

        var result = service.status(accepted.runId(), "admin");
        assertThat(result.status()).isEqualTo("PARTIAL");
        assertThat(result.scopeCount()).isEqualTo(2);
        assertThat(result.completedScopeCount()).isEqualTo(2);
        assertThat(result.incompleteScopeCount()).isEqualTo(1);
        assertThat(result.collectedObjectCount()).isEqualTo(3);
        assertThat(result.attemptNo()).isEqualTo(1);
        assertThat(result.startedAt()).isNotNull();

        jdbc.update("UPDATE secret_scan_runs SET failure_code = 'VALIDATION_INCONCLUSIVE' WHERE run_id = ?",
                accepted.runId());
        assertThat(service.status(accepted.runId(), "admin").failureCode())
                .isEqualTo("VALIDATION_INCONCLUSIVE");

        jdbc.update("""
                UPDATE secret_jobs SET status = 'FAILED', last_error_code = 'SOURCE_ACCESS_DENIED'
                WHERE connection_id = ?
                """, connection);
        jdbc.update("""
                UPDATE secret_scan_runs SET result_status = 'FAILED', failure_code = 'unsafe:raw-provider-error'
                WHERE run_id = ?
                """, accepted.runId());
        var failed = service.status(accepted.runId(), "admin");
        assertThat(failed.status()).isEqualTo("FAILED");
        assertThat(failed.failureCode()).isEqualTo("UNSPECIFIED_FAILURE");
    }

    @Test
    void concurrentRequestsForOneConnectionReuseOneReservation() throws Exception {
        long connection = connection("ACTIVE", null);
        scope(connection, "fixtures/", true);
        var barrier = new CyclicBarrier(2);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var futures = new ArrayList<Future<Long>>();
            for (int i = 0; i < 2; i++) {
                futures.add(executor.submit(() -> {
                    barrier.await(5, TimeUnit.SECONDS);
                    return service.register(new SecretRunRequest(connection, null), "admin").runId();
                }));
            }
            assertThat(futures.get(0).get(10, TimeUnit.SECONDS))
                    .isEqualTo(futures.get(1).get(10, TimeUnit.SECONDS));
        }
        assertThat(count("secret_jobs")).isEqualTo(1);
    }

    @Test
    void concurrentSameKeyForDifferentConnectionsReservesOnlyOne() throws Exception {
        long first = connection("ACTIVE", null);
        long second = connection("ACTIVE", null);
        scope(first, "one/", true);
        scope(second, "two/", true);
        var barrier = new CyclicBarrier(2);
        try (var executor = Executors.newFixedThreadPool(2)) {
            var results = new ArrayList<Future<String>>();
            for (long id : new long[]{first, second}) {
                results.add(executor.submit(() -> {
                    barrier.await(5, TimeUnit.SECONDS);
                    try {
                        service.register(new SecretRunRequest(id, "same-key"), "admin");
                        return "ACCEPTED";
                    } catch (ApiException e) {
                        return e.errorCode().name();
                    }
                }));
            }
            assertThat(java.util.List.of(results.get(0).get(10, TimeUnit.SECONDS),
                    results.get(1).get(10, TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder("ACCEPTED", "CONFLICT");
        }
        assertThat(count("secret_jobs")).isEqualTo(1);
    }

    private long connection(String status, OffsetDateTime nextDue) {
        return connection("GITHUB", status, nextDue);
    }

    private long connection(String provider, String status, OffsetDateTime nextDue) {
        return jdbc.queryForObject("""
                INSERT INTO secret_connections
                    (provider, display_name, auth_ref, status, scope_version, next_due_at)
                VALUES (?, 'Test connection', ?, ?, 1, ?)
                RETURNING connection_id
                """, Long.class, provider,
                "AWS".equals(provider) ? "aws-profile:test" : "test-only-ref",
                status, nextDue);
    }

    private long scope(long connectionId, String key, boolean enabled) {
        return jdbc.queryForObject("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref, history_limit, enabled)
                VALUES (?, ?, 1, 'GITHUB_REPOSITORY_FILES', 'Logssey/test-find-key@main:fixtures/',
                        'CURRENT_COMMIT_ONLY', ?)
                RETURNING scope_id
                """, Long.class, connectionId, key, enabled);
    }

    private long count(String table) {
        return jdbc.queryForObject("SELECT COUNT(*) FROM " + table, Long.class);
    }

    private void assertConflict(Runnable action) {
        assertCode(ErrorCode.CONFLICT, action);
    }

    private void assertCode(ErrorCode expected, Runnable action) {
        assertThatThrownBy(action::run).isInstanceOf(ApiException.class)
                .satisfies(error -> assertThat(((ApiException) error).errorCode()).isEqualTo(expected));
    }
}
