package com.logssey.secretworker.aws;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import com.logssey.secretworker.SecretJobExecutionService;
import com.logssey.secretworker.SecretJobProperties;
import com.logssey.secretworker.SecretJobTestSupport;
import com.logssey.secretworker.aws.metadata.AwsMetadataCollector;
import com.logssey.secretworker.aws.metadata.AwsMetadataPageClient;

import static org.assertj.core.api.Assertions.assertThat;

class AwsSecretJobProcessorTest {
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final String ACCOUNT = "123456789012";
    private static final String ACCESS_KEY_ID = "AKIAABCDEFGHIJKLMNOP";
    private static JdbcTemplate jdbc;
    private static SecretJobExecutionService execution;
    private static SecretJobProperties properties;

    @BeforeAll
    static void startDatabase() {
        POSTGRES.start();
        var datasource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(),
                POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(datasource).load().migrate();
        jdbc = new JdbcTemplate(datasource);
        properties = new SecretJobProperties(false, Duration.ofSeconds(30), Duration.ofMinutes(5),
                10, Duration.ofSeconds(1), Duration.ofSeconds(8));
        execution = SecretJobTestSupport.execution(jdbc, properties,
                new DataSourceTransactionManager(datasource));
    }

    @AfterAll static void stopDatabase() { POSTGRES.stop(); }

    @BeforeEach
    void clean() { jdbc.execute("TRUNCATE secret_connections RESTART IDENTITY CASCADE"); }

    @Test
    void completedIamInventoryIsMetadataOnlyAndDeduplicatesAcrossRuns() {
        long connection = connection();
        long scope = scope(connection, "IAM_ACCESS_KEY_METADATA",
                "aws://" + ACCOUNT + "/global/iam/access-keys");
        execute(run(connection, scope), new FakeGateway());
        assertThat(jdbc.queryForObject("SELECT result_status FROM secret_scan_runs", String.class))
                .isEqualTo("SUCCEEDED");
        assertThat(jdbc.queryForObject("SELECT detection_status FROM secret_scan_runs", String.class))
                .isEqualTo("SKIPPED");
        assertThat(jdbc.queryForObject("SELECT validation_status FROM secret_scan_runs", String.class))
                .isEqualTo("SKIPPED");
        assertThat(jdbc.queryForMap("""
                SELECT component_state, lifecycle_status, fingerprint IS NULL AS no_fingerprint,
                       external_key_ref, masked_label FROM secret_credential_sets
                """))
                .containsEntry("component_state", "METADATA_ONLY")
                .containsEntry("lifecycle_status", "UNKNOWN")
                .containsEntry("no_fingerprint", true);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_validation_attempts", Long.class))
                .isZero();

        execute(run(connection, scope), new FakeGateway());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_credential_sets", Long.class))
                .isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_occurrences", Long.class))
                .isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_aws_access_key_observations", Long.class))
                .isEqualTo(2);
        String stored = jdbc.queryForMap("""
                SELECT c.external_key_ref, c.masked_label, o.source_object_ref,
                       o.location_key, m.last_used_service, m.last_used_region
                FROM secret_credential_sets c
                JOIN secret_occurrences o USING (credential_set_id)
                JOIN secret_aws_access_key_observations m USING (credential_set_id)
                LIMIT 1
                """).toString();
        assertThat(stored).doesNotContain(ACCESS_KEY_ID, "alice", "secret access key");
        assertThat(stored).contains("hmac:test-v1:");
    }

    @Test
    void unsupportedScopeIsExplicitlyPartialAndNeverRead() {
        long connection = connection();
        long iam = scope(connection, "IAM_ACCESS_KEY_METADATA",
                "aws://" + ACCOUNT + "/global/iam/access-keys");
        scope(connection, "AWS_SECRET_VALUE", "aws://" + ACCOUNT + "/ap-northeast-1/secret/value");
        var gateway = new FakeGateway();
        execute(run(connection, iam), gateway);
        assertThat(jdbc.queryForObject("SELECT result_status FROM secret_scan_runs", String.class))
                .isEqualTo("PARTIAL");
        assertThat(jdbc.queryForMap("""
                SELECT collection_status, unsupported_reason FROM secret_run_scopes
                WHERE collection_status = 'SKIPPED'
                """))
                .containsEntry("unsupported_reason", "AWS_SERVICE_UNSUPPORTED");
        assertThat(gateway.accessKeyCalls).isEqualTo(1);
    }

    @Test
    void onlyCompleteUserKeyListingCanMarkPreviouslySeenKeyMissing() {
        long connection = connection();
        long scope = scope(connection, "IAM_ACCESS_KEY_METADATA",
                "aws://" + ACCOUNT + "/global/iam/access-keys");
        execute(run(connection, scope), new FakeGateway());
        var partial = new FakeGateway();
        partial.emptyKeys = true;
        partial.rootKeys = 1;
        execute(run(connection, scope), partial);
        assertThat(jdbc.queryForObject("SELECT presence_status FROM secret_occurrences", String.class))
                .isEqualTo("PRESENT");
        assertThat(jdbc.queryForObject("""
                SELECT result_status FROM secret_scan_runs ORDER BY run_id DESC LIMIT 1
                """, String.class)).isEqualTo("PARTIAL");

        var complete = new FakeGateway();
        complete.emptyKeys = true;
        execute(run(connection, scope), complete);
        assertThat(jdbc.queryForObject("SELECT presence_status FROM secret_occurrences", String.class))
                .isEqualTo("MISSING");
        assertThat(jdbc.queryForObject("SELECT last_complete_coverage_at IS NOT NULL FROM secret_occurrences",
                Boolean.class)).isTrue();
    }

    @Test
    void mismatchedProfileReferenceDoesNotReachAwsGateway() {
        long connection = connection();
        long scope = scope(connection, "IAM_ACCESS_KEY_METADATA",
                "aws://" + ACCOUNT + "/global/iam/access-keys");
        jdbc.update("UPDATE secret_connections SET auth_ref = 'aws-profile:wrong' WHERE connection_id = ?",
                connection);
        long run = run(connection, scope);
        var gateway = new FakeGateway();
        var processor = new AwsSecretJobProcessor(jdbc, new AwsIamCollector(gateway),
                new AwsMetadataCollector(new FakeMetadataPages()), gateway,
                new AwsIamMetadataRepository(jdbc, new AwsMetadataIdentity(new byte[32], "test-v1")),
                properties, "test");
        var job = execution.claimNextJob("AWS").orElseThrow();
        assertThat(job.runId()).isEqualTo(run);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> processor.process(job, execution))
                .isInstanceOf(com.logssey.secretworker.SecretJobFailure.class);
        assertThat(gateway.accountCalls).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_credential_sets", Long.class))
                .isZero();
    }

    @Test
    void mixedIamAndRegionalMetadataScopesUseOneJobAndStoreOnlyCounts() {
        long connection = connection();
        scope(connection, "IAM_ACCESS_KEY_METADATA", "aws://" + ACCOUNT + "/global/iam/access-keys");
        scope(connection, "AWS_SECRETS_MANAGER_METADATA",
                "aws://" + ACCOUNT + "/ap-northeast-2/secrets-manager/all");
        scope(connection, "AWS_SSM_PARAMETER_METADATA",
                "aws://" + ACCOUNT + "/us-east-1/ssm/parameters");
        scope(connection, "AWS_S3_BUCKET_METADATA", "aws://" + ACCOUNT + "/global/s3/buckets");
        var gateway = new FakeGateway();
        var pages = new FakeMetadataPages();
        pages.secretCount = 2;
        pages.parameterCount = 3;
        pages.bucketCount = 4;
        execute(run(connection, 0), gateway, pages);

        assertThat(jdbc.queryForObject("SELECT result_status FROM secret_scan_runs", String.class))
                .isEqualTo("SUCCEEDED");
        assertThat(jdbc.queryForList("""
                SELECT s.content_type, rs.object_count, rs.collection_status
                FROM secret_run_scopes rs JOIN secret_connection_scopes s USING (scope_id)
                ORDER BY rs.run_scope_id
                """))
                .extracting(row -> row.get("object_count"))
                .containsExactlyInAnyOrder(1L, 2L, 3L, 4L);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_credential_sets", Long.class))
                .isEqualTo(1);
        assertThat(pages.secretCalls).isEqualTo(1);
        assertThat(pages.parameterCalls).isEqualTo(1);
        assertThat(pages.bucketCalls).isEqualTo(1);
        assertThat(gateway.accountCalls).isEqualTo(2); // IAM check and one cached metadata check.
    }

    @Test
    void mismatchedMetadataAccountNeverListsThatService() {
        long connection = connection();
        scope(connection, "IAM_ACCESS_KEY_METADATA", "aws://" + ACCOUNT + "/global/iam/access-keys");
        scope(connection, "AWS_SECRETS_MANAGER_METADATA",
                "aws://000000000000/us-east-1/secrets-manager/all");
        var pages = new FakeMetadataPages();
        execute(run(connection, 0), new FakeGateway(), pages);

        assertThat(pages.secretCalls).isZero();
        assertThat(jdbc.queryForMap("""
                SELECT rs.collection_status, rs.failure_code
                FROM secret_run_scopes rs JOIN secret_connection_scopes s USING (scope_id)
                WHERE s.content_type = 'AWS_SECRETS_MANAGER_METADATA'
                """))
                .containsEntry("collection_status", "FAILED")
                .containsEntry("failure_code", "AWS_ACCOUNT_MISMATCH");
        assertThat(jdbc.queryForObject("SELECT result_status FROM secret_scan_runs", String.class))
                .isEqualTo("PARTIAL");
    }

    @Test
    void metadataSecondPageFailureKeepsFirstPageCountAndPartialCoverage() {
        long connection = connection();
        scope(connection, "IAM_ACCESS_KEY_METADATA", "aws://" + ACCOUNT + "/global/iam/access-keys");
        scope(connection, "AWS_SECRETS_MANAGER_METADATA",
                "aws://" + ACCOUNT + "/us-east-1/secrets-manager/all");
        var pages = new FakeMetadataPages();
        pages.failAfterSecretFirstPage = true;
        execute(run(connection, 0), new FakeGateway(), pages);

        assertThat(jdbc.queryForMap("""
                SELECT rs.collection_status, rs.object_count, rs.failure_code
                FROM secret_run_scopes rs JOIN secret_connection_scopes s USING (scope_id)
                WHERE s.content_type = 'AWS_SECRETS_MANAGER_METADATA'
                """))
                .containsEntry("collection_status", "PARTIAL")
                .containsEntry("object_count", 2L)
                .containsEntry("failure_code", "AWS_ACCESS_DENIED");
        assertThat(jdbc.queryForObject("SELECT result_status FROM secret_scan_runs", String.class))
                .isEqualTo("PARTIAL");
        assertThat(pages.secretCalls).isEqualTo(2);
    }

    @Test
    void emptyMetadataFirstPageThenDeniedNextPageStaysPartial() {
        long connection = connection();
        scope(connection, "AWS_SECRETS_MANAGER_METADATA",
                "aws://" + ACCOUNT + "/us-east-1/secrets-manager/all");
        var pages = new FakeMetadataPages();
        pages.failAfterSecretFirstPage = true;
        pages.secretFirstPageCount = 0;
        execute(run(connection, 0), new FakeGateway(), pages);

        assertThat(jdbc.queryForMap("""
                SELECT collection_status, object_count, failure_code
                FROM secret_run_scopes
                """))
                .containsEntry("collection_status", "PARTIAL")
                .containsEntry("object_count", 0L)
                .containsEntry("failure_code", "AWS_ACCESS_DENIED");
        assertThat(jdbc.queryForObject("SELECT result_status FROM secret_scan_runs", String.class))
                .isEqualTo("PARTIAL");
        assertThat(pages.secretCalls).isEqualTo(2);
    }

    private static void execute(long run, FakeGateway gateway) {
        execute(run, gateway, new FakeMetadataPages());
    }

    private static void execute(long run, FakeGateway gateway, FakeMetadataPages pages) {
        var processor = new AwsSecretJobProcessor(jdbc, new AwsIamCollector(gateway),
                new AwsMetadataCollector(pages), gateway,
                new AwsIamMetadataRepository(jdbc, new AwsMetadataIdentity(new byte[32], "test-v1")),
                properties, "test");
        var job = execution.claimNextJob("AWS").orElseThrow();
        assertThat(job.runId()).isEqualTo(run);
        processor.process(job, execution);
        assertThat(execution.complete(job.jobId(), job.leaseToken())).isTrue();
    }

    private static long connection() {
        return jdbc.queryForObject("""
                INSERT INTO secret_connections
                    (provider, display_name, auth_ref, status, scope_version)
                VALUES ('AWS', 'test AWS account', 'aws-profile:test', 'ACTIVE', 1)
                RETURNING connection_id
                """, Long.class);
    }

    private static long scope(long connection, String type, String ref) {
        return jdbc.queryForObject("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type,
                     approved_ref, history_limit, enabled)
                VALUES (?, ?, 1, ?, ?, 'CURRENT_STATE_ONLY', true)
                RETURNING scope_id
                """, Long.class, connection, type, type, ref);
    }

    private static long run(long connection, long ignored) {
        OffsetDateTime now = Instant.now().atOffset(ZoneOffset.UTC);
        long job = jdbc.queryForObject("""
                INSERT INTO secret_jobs
                    (kind, connection_id, scheduled_at, available_at,
                     attempt_no, max_attempts, status)
                VALUES ('FULL_SCAN', ?, ?, ?, 0, 3, 'PENDING')
                RETURNING job_id
                """, Long.class, connection, now, now.minusSeconds(5));
        long run = jdbc.queryForObject("""
                INSERT INTO secret_scan_runs
                    (job_id, connection_id, trigger_type, scope_version,
                     scheduled_at, requested_at, collection_status,
                     detection_status, validation_status, result_status)
                VALUES (?, ?, 'MANUAL', 1, ?, ?, 'PENDING', 'PENDING', 'PENDING', 'PENDING')
                RETURNING run_id
                """, Long.class, job, connection, now, now);
        jdbc.update("""
                INSERT INTO secret_run_scopes (run_id, scope_id, collection_status)
                SELECT ?, scope_id, 'PENDING' FROM secret_connection_scopes
                WHERE connection_id = ? AND enabled
                """, run, connection);
        return run;
    }

    private static final class FakeGateway implements AwsIamGateway {
        int accessKeyCalls;
        int accountCalls;
        int rootKeys;
        boolean emptyKeys;
        @Override public String accountId() { accountCalls++; return ACCOUNT; }
        @Override public Page<String> users(String marker) {
            return new Page<>(List.of("alice"), null);
        }
        @Override public Page<AccessKey> accessKeys(String userName, String marker) {
            accessKeyCalls++;
            if (emptyKeys) return new Page<>(List.of(), null);
            return new Page<>(List.of(new AccessKey(ACCESS_KEY_ID, userName,
                    "Active", Instant.parse("2026-01-01T00:00:00Z"))), null);
        }
        @Override public LastUsed lastUsed(String accessKeyId) {
            return new LastUsed(Instant.parse("2026-02-01T00:00:00Z"),
                    "Amazon S3", "ap-northeast-1");
        }
        @Override public int rootAccessKeyCount() { return rootKeys; }
    }

    private static final class FakeMetadataPages implements AwsMetadataPageClient {
        int secretCount;
        int parameterCount;
        int bucketCount;
        int secretCalls;
        int parameterCalls;
        int bucketCalls;
        boolean failAfterSecretFirstPage;
        int secretFirstPageCount = 2;

        @Override public Page listSecrets(String region, String nextToken) {
            secretCalls++;
            if (failAfterSecretFirstPage) {
                if (nextToken != null) throw new Failure(AwsMetadataCollector.GapCode.ACCESS_DENIED);
                return new Page(secretFirstPageCount, "next");
            }
            return new Page(secretCount, null);
        }

        @Override public Page describeParameters(String region, String nextToken) {
            parameterCalls++;
            return new Page(parameterCount, null);
        }

        @Override public Page listBuckets(String nextToken) {
            bucketCalls++;
            return new Page(bucketCount, null);
        }
    }
}
