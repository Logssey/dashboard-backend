package com.logssey.secretworker.aws;

import java.nio.charset.StandardCharsets;
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
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import com.logssey.secretworker.SecretJobExecutionService;
import com.logssey.secretworker.SecretJobFailure;
import com.logssey.secretworker.SecretJobFailureCode;
import com.logssey.secretworker.SecretJobProperties;
import com.logssey.secretworker.SecretJobTestSupport;
import com.logssey.secretworker.aws.metadata.AwsMetadataCollector;
import com.logssey.secretworker.aws.metadata.AwsMetadataPageClient;
import com.logssey.secretworker.aws.content.AwsContentCollector;
import com.logssey.secretworker.aws.content.AwsContentPipeline;
import com.logssey.secretworker.aws.content.AwsContentReader;
import com.logssey.secretworker.aws.content.AwsContentScope;
import com.logssey.secretworker.detection.SecretFindingNormalizer;
import com.logssey.secretworker.detection.SecretFindingRepository;
import com.logssey.secretworker.detector.GitleaksFinding;
import com.logssey.secretworker.detector.GitleaksScanResult;
import com.logssey.secretworker.detector.SecretContentDetector;
import com.logssey.secretworker.validation.AwsValidationResult;
import com.logssey.secretworker.validation.SecretValidationAttemptRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;

class AwsSecretJobProcessorTest {
    private static final PostgreSQLContainer POSTGRES = new com.logssey.secret.testing.SecretTestPostgres();
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
        assertThat(jdbc.queryForMap("SELECT scope_outcome,detection_stage_status,detection_reason_code,validation_stage_status FROM secret_scope_outcomes"))
                .containsEntry("scope_outcome","SUCCEEDED").containsEntry("detection_stage_status","SKIPPED")
                .containsEntry("detection_reason_code","NOT_APPLICABLE_METADATA").containsEntry("validation_stage_status","SKIPPED");
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

    @Test
    void exactValueScopeIsDisabledByDefaultAndMakesNoValueCall() {
        long connection = connection();
        scope(connection, "IAM_ACCESS_KEY_METADATA", "aws://" + ACCOUNT + "/global/iam/access-keys");
        contentScope(connection, "AWS_SECRETS_MANAGER_VALUE", exactSecretRef(ACCOUNT), 1);
        var gateway = new FakeGateway();
        var reader = new FakeContentReader();
        // The default constructor has no content pipeline: even a configured reader is unreachable.
        execute(run(connection, 0), gateway);

        assertThat(reader.calls).isZero();
        assertThat(jdbc.queryForMap("""
                SELECT collection_status, failure_code FROM secret_run_scopes rs
                JOIN secret_connection_scopes s USING (scope_id)
                WHERE s.content_type = 'AWS_SECRETS_MANAGER_VALUE'
                """))
                .containsEntry("collection_status", "SKIPPED")
                .containsEntry("failure_code", "AWS_CONTENT_READ_DISABLED");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_tool_runs", Long.class)).isZero();
    }

    @Test
    void accountMismatchCannotReachExactValueReader() {
        long connection = connection();
        scope(connection, "IAM_ACCESS_KEY_METADATA", "aws://" + ACCOUNT + "/global/iam/access-keys");
        contentScope(connection, "AWS_SECRETS_MANAGER_VALUE", exactSecretRef("000000000000"), 1);
        var reader = new FakeContentReader();
        executeContent(run(connection, 0), new FakeGateway(), reader);

        assertThat(reader.calls).isZero();
        assertThat(jdbc.queryForMap("""
                SELECT collection_status, failure_code FROM secret_run_scopes rs
                JOIN secret_connection_scopes s USING (scope_id)
                WHERE s.content_type = 'AWS_SECRETS_MANAGER_VALUE'
                """))
                .containsEntry("collection_status", "FAILED")
                .containsEntry("failure_code", "AWS_ACCOUNT_MISMATCH");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_tool_runs", Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT result_status FROM secret_scan_runs", String.class))
                .isEqualTo("PARTIAL");
    }

    @Test
    void exactValueIsDetectedNormalizedAndStoredWithoutRawMaterial() {
        long connection = connection();
        long scopeId = contentScope(connection, "AWS_SECRETS_MANAGER_VALUE", exactSecretRef(ACCOUNT), 1);
        String id = "AKIA" + "ABCDEFGHIJKLMNOP";
        String secret = "aB3/".repeat(10);
        var reader = new FakeContentReader();
        reader.bytes = ("AWS_ACCESS_KEY_ID=" + id + "\nAWS_SECRET_ACCESS_KEY=" + secret + "\n")
                .getBytes(StandardCharsets.UTF_8);
        byte[] owned = reader.bytes;
        long firstRun = run(connection, scopeId);
        executeContent(firstRun, new FakeGateway(), reader);

        assertThat(reader.calls).isEqualTo(1);
        assertThat(owned).containsOnly((byte) 0);
        assertThat(jdbc.queryForMap("""
                SELECT result_status, collection_status, detection_status, validation_status
                FROM secret_scan_runs WHERE run_id = ?
                """, firstRun))
                .containsEntry("result_status", "SUCCEEDED")
                .containsEntry("collection_status", "SUCCEEDED")
                .containsEntry("detection_status", "SUCCEEDED")
                .containsEntry("validation_status", "SKIPPED");
        assertThat(jdbc.queryForMap("SELECT component_state, issuer FROM secret_credential_sets"))
                .containsEntry("component_state", "CONFIRMED")
                .containsEntry("issuer", "AWS");
        assertThat(jdbc.queryForMap("SELECT result, reason_code FROM secret_validation_attempts"))
                .containsEntry("result", "UNCHECKED")
                .containsEntry("reason_code", "DISABLED");
        assertThat(jdbc.queryForObject("SELECT source_object_ref FROM secret_occurrences", String.class))
                .isEqualTo("aws-content-scope:" + scopeId);

        String persisted = String.join("\n", List.of(
                jdbc.queryForList("SELECT to_jsonb(t)::text FROM secret_credential_sets t", String.class).toString(),
                jdbc.queryForList("SELECT to_jsonb(t)::text FROM secret_occurrences t", String.class).toString(),
                jdbc.queryForList("SELECT to_jsonb(t)::text FROM secret_findings t", String.class).toString(),
                jdbc.queryForList("SELECT to_jsonb(t)::text FROM secret_tool_runs t", String.class).toString(),
                jdbc.queryForList("SELECT to_jsonb(t)::text FROM secret_validation_attempts t", String.class).toString()));
        assertThat(persisted).doesNotContain(id, secret, "fixture-secret");

        reader.bytes = ("AWS_ACCESS_KEY_ID=" + id + "\nAWS_SECRET_ACCESS_KEY=" + secret + "\n")
                .getBytes(StandardCharsets.UTF_8);
        executeContent(run(connection, scopeId), new FakeGateway(), reader);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_credential_sets", Long.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_occurrences", Long.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_findings", Long.class)).isEqualTo(4);
    }

    @Test
    void valueReadFailureDoesNotStopAnotherApprovedScope() {
        long connection = connection();
        scope(connection, "IAM_ACCESS_KEY_METADATA", "aws://" + ACCOUNT + "/global/iam/access-keys");
        contentScope(connection, "AWS_SSM_PARAMETER_VALUE", "aws://" + ACCOUNT
                + "/ap-northeast-2/ssm/parameter/arn%3Aaws%3Assm%3Aap-northeast-2%3A"
                + ACCOUNT + "%3Aparameter%2Ffixture", 1);
        var reader = new FakeContentReader();
        reader.failure = AwsContentReader.FailureCode.ACCESS_DENIED;
        executeContent(run(connection, 0), new FakeGateway(), reader);

        assertThat(reader.calls).isEqualTo(1);
        assertThat(jdbc.queryForMap("""
                SELECT collection_status, failure_code FROM secret_run_scopes rs
                JOIN secret_connection_scopes s USING (scope_id)
                WHERE s.content_type = 'AWS_SSM_PARAMETER_VALUE'
                """))
                .containsEntry("collection_status", "FAILED")
                .containsEntry("failure_code", "AWS_CONTENT_ACCESS_DENIED");
        assertThat(jdbc.queryForMap("""
                SELECT result_status, collection_status, detection_status FROM secret_scan_runs
                """))
                .containsEntry("result_status", "PARTIAL")
                .containsEntry("collection_status", "PARTIAL")
                .containsEntry("detection_status", "PARTIAL");
    }

    @Test
    void lostLeaseDuringValueReadEscapesAsOwnershipFailure() {
        long connection = connection();
        contentScope(connection, "AWS_SECRETS_MANAGER_VALUE", exactSecretRef(ACCOUNT), 1);
        var reader = new FakeContentReader();
        reader.bytes = "local synthetic fixture".getBytes(StandardCharsets.UTF_8);
        byte[] owned = reader.bytes;
        long run = run(connection, 0);
        reader.onRead = () -> jdbc.update("""
                UPDATE secret_jobs SET lease_owner = 'stolen-by-test'
                WHERE job_id = (SELECT job_id FROM secret_scan_runs WHERE run_id = ?)
                """, run);

        assertThatThrownBy(() -> executeContent(run, new FakeGateway(), reader))
                .isInstanceOf(SecretJobFailure.class)
                .satisfies(error -> assertThat(((SecretJobFailure) error).code())
                        .isEqualTo(SecretJobFailureCode.LEASE_EXPIRED));
        assertThat(reader.calls).isEqualTo(1);
        assertThat(owned).containsOnly((byte) 0);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_credential_sets", Long.class)).isZero();
    }

    @Test
    void expiredLeaseImmediatelyBeforeValueApiPreventsReaderCall() {
        long connection = connection();
        contentScope(connection, "AWS_SECRETS_MANAGER_VALUE", exactSecretRef(ACCOUNT), 1);
        var reader = new FakeContentReader();
        long run = run(connection, 0);
        var controlledExecution = spy(execution);
        doReturn(false).when(controlledExecution).renewLease(anyLong(), anyString());

        assertThatThrownBy(() -> executeContent(run, new FakeGateway(), reader, controlledExecution))
                .isInstanceOf(SecretJobFailure.class)
                .satisfies(error -> assertThat(((SecretJobFailure) error).code())
                        .isEqualTo(SecretJobFailureCode.LEASE_EXPIRED));
        assertThat(reader.calls).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_tool_runs", Long.class)).isZero();
    }

    @Test
    void exactAwsValueRechecksProveAbsenceOnlyAfterACompleteComparableRead() {
        String[][] scopes = {
                {"AWS_SECRETS_MANAGER_VALUE", exactSecretRef(ACCOUNT)},
                {"AWS_SSM_PARAMETER_VALUE", "aws://" + ACCOUNT + "/ap-northeast-2/ssm/parameter/arn%3Aaws%3Assm%3Aap-northeast-2%3A" + ACCOUNT + "%3Aparameter%2Ffixture"},
                {"AWS_S3_OBJECT_CONTENT", "aws://" + ACCOUNT + "/ap-northeast-2/s3/object/example-bucket/fixture.env"}
        };
        for (int i = 0; i < scopes.length; i++) {
            if (i > 0) clean();
            var seed = prepareContentRecheck(scopes[i][0], scopes[i][1]);
            var reader = new FakeContentReader();
            reader.bytes = "CONFIG=credential-removed\n".getBytes(StandardCharsets.UTF_8);
            executeContent(seed.runId(), new FakeGateway(), reader);
            assertThat(reader.calls).isEqualTo(1);
            assertThat(jdbc.queryForMap("SELECT status,runtime_fingerprint_version FROM secret_case_revalidations WHERE run_id=?", seed.runId()))
                    .containsEntry("status", "MISSING")
                    .containsEntry("runtime_fingerprint_version", "test-v1");
            assertThat(jdbc.queryForObject("SELECT presence_status FROM secret_occurrences WHERE occurrence_id=?", String.class, seed.occurrenceId()))
                    .isEqualTo("MISSING");
            assertThat(jdbc.queryForObject("SELECT action_status FROM secret_response_cases WHERE case_id=?", String.class, seed.caseId()))
                    .isEqualTo("REVALIDATION_PENDING");
        }
    }

    @Test
    void sameKeyStillInAwsValueKeepsTheLocationPresent() {
        var seed = prepareContentRecheck("AWS_SECRETS_MANAGER_VALUE", exactSecretRef(ACCOUNT));
        var reader = new FakeContentReader();
        reader.bytes = credentialContent();
        executeContent(seed.runId(), new FakeGateway(), reader);
        assertThat(jdbc.queryForObject("SELECT status FROM secret_case_revalidations WHERE run_id=?", String.class, seed.runId()))
                .isEqualTo("PRESENT");
        assertThat(jdbc.queryForObject("SELECT presence_status FROM secret_occurrences WHERE occurrence_id=?", String.class, seed.occurrenceId()))
                .isEqualTo("PRESENT");
    }

    @Test
    void changedAwsValueDoesNotSubstituteTheReplacementKeyForTheOriginal() {
        var seed = prepareContentRecheck("AWS_SECRETS_MANAGER_VALUE", exactSecretRef(ACCOUNT));
        var reader = new FakeContentReader();
        reader.bytes = new String(credentialContent(), StandardCharsets.UTF_8)
                .replace("ABCDEFGHIJKLMNOP", "QRSTUVWXYZABCDEF").getBytes(StandardCharsets.UTF_8);
        executeContent(seed.runId(), new FakeGateway(), reader);
        assertThat(jdbc.queryForObject("SELECT status FROM secret_case_revalidations WHERE run_id=?", String.class, seed.runId()))
                .isEqualTo("MISSING");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_credential_sets WHERE component_state='CONFIRMED'", Long.class))
                .isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_occurrences WHERE presence_status='PRESENT'", Long.class))
                .isEqualTo(1);
    }

    @Test
    void missingOrUnreadableAwsResourceNeverProvesTheKeyWasRemoved() {
        for (var failure : List.of(AwsContentReader.FailureCode.NOT_FOUND, AwsContentReader.FailureCode.ACCESS_DENIED)) {
            clean();
            var seed = prepareContentRecheck("AWS_SECRETS_MANAGER_VALUE", exactSecretRef(ACCOUNT));
            var reader = new FakeContentReader();
            reader.failure = failure;
            var job = execution.claimNextJob("AWS").orElseThrow();
            assertThatThrownBy(() -> contentProcessor(new FakeGateway(), reader, execution).process(job, execution))
                    .isInstanceOf(SecretJobFailure.class);
            assertThat(execution.fail(job.jobId(), job.leaseToken(), SecretJobFailureCode.SOURCE_ACCESS_DENIED, false))
                    .isTrue();
            assertThat(jdbc.queryForObject("SELECT status FROM secret_case_revalidations WHERE run_id=?", String.class, seed.runId()))
                    .isEqualTo("UNKNOWN");
            assertThat(jdbc.queryForObject("SELECT presence_status FROM secret_occurrences WHERE occurrence_id=?", String.class, seed.occurrenceId()))
                    .isEqualTo("UNKNOWN");
            assertThat(jdbc.queryForObject("SELECT failure_code FROM secret_run_scopes WHERE run_id=?", String.class, seed.runId()))
                    .isEqualTo("AWS_CONTENT_" + failure.name());
        }
    }

    @Test
    void staleAwsRecheckCannotReadAnotherResourceOrUseChangedIdentity() {
        for (String change : List.of("UPDATE secret_connection_scopes SET revision=revision+1",
                "UPDATE secret_credential_sets SET fingerprint=decode(md5(random()::text),'hex')",
                "UPDATE secret_occurrences SET source_object_ref='aws-content-scope:999999'",
                "UPDATE secret_case_occurrences SET action_cycle=action_cycle+1")) {
            clean();
            prepareContentRecheck("AWS_SECRETS_MANAGER_VALUE", exactSecretRef(ACCOUNT));
            jdbc.update(change);
            var reader = new FakeContentReader();
            var job = execution.claimNextJob("AWS").orElseThrow();
            assertThatThrownBy(() -> contentProcessor(new FakeGateway(), reader, execution).process(job, execution))
                    .isInstanceOf(SecretJobFailure.class);
            assertThat(reader.calls).isZero();
        }
    }

    @Test
    void lostAwsRecheckLeasePreventsReaderCallAndCannotPublishAbsence() {
        var seed = prepareContentRecheck("AWS_SECRETS_MANAGER_VALUE", exactSecretRef(ACCOUNT));
        var reader = new FakeContentReader();
        var controlled = spy(execution);
        doReturn(false).when(controlled).renewLease(anyLong(), anyString());
        var job = controlled.claimNextJob("AWS").orElseThrow();
        assertThatThrownBy(() -> contentProcessor(new FakeGateway(), reader, controlled).process(job, controlled))
                .isInstanceOf(SecretJobFailure.class);
        assertThat(reader.calls).isZero();
        assertThat(jdbc.queryForObject("SELECT status FROM secret_case_revalidations WHERE run_id=?", String.class, seed.runId()))
                .isEqualTo("PENDING");
        assertThat(jdbc.queryForObject("SELECT presence_status FROM secret_occurrences WHERE occurrence_id=?", String.class, seed.occurrenceId()))
                .isEqualTo("UNKNOWN");
    }

    @Test
    void unnormalizedCandidatesCannotProveAwsCredentialRemoval() {
        var seed = prepareContentRecheck("AWS_SECRETS_MANAGER_VALUE", exactSecretRef(ACCOUNT));
        var reader = new FakeContentReader();
        reader.bytes = new String(credentialContent(), StandardCharsets.UTF_8)
                .replace("AWS_SECRET_ACCESS_KEY", "UNRELATED_CREDENTIAL").getBytes(StandardCharsets.UTF_8);
        var job = execution.claimNextJob("AWS").orElseThrow();
        assertThatThrownBy(() -> contentProcessor(new FakeGateway(), reader, execution).process(job, execution))
                .isInstanceOf(SecretJobFailure.class);
        execution.fail(job.jobId(), job.leaseToken(), SecretJobFailureCode.SOURCE_ACCESS_DENIED, false);
        assertThat(jdbc.queryForObject("SELECT status FROM secret_case_revalidations WHERE run_id=?", String.class, seed.runId()))
                .isEqualTo("UNKNOWN");
        assertThat(jdbc.queryForObject("SELECT failure_code FROM secret_run_scopes WHERE run_id=?", String.class, seed.runId()))
                .isEqualTo("DETECTOR_NORMALIZATION_INCOMPLETE");
    }

    @Test
    void remainingPartialAwsKeyCannotBeReportedAsFullyRemoved() {
        var seed = prepareContentRecheck("AWS_SECRETS_MANAGER_VALUE", exactSecretRef(ACCOUNT));
        var reader = new FakeContentReader();
        reader.bytes = "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n".getBytes(StandardCharsets.UTF_8);
        var job = execution.claimNextJob("AWS").orElseThrow();
        assertThatThrownBy(() -> contentProcessor(new FakeGateway(), reader, execution).process(job, execution))
                .isInstanceOf(SecretJobFailure.class);
        execution.fail(job.jobId(), job.leaseToken(), SecretJobFailureCode.SOURCE_ACCESS_DENIED, false);
        assertThat(jdbc.queryForObject("SELECT status FROM secret_case_revalidations WHERE run_id=?", String.class, seed.runId()))
                .isEqualTo("UNKNOWN");
    }

    private Recheck prepareContentRecheck(String type, String ref) {
        long connection = connection();
        long scopeId = contentScope(connection, type, ref, 1);
        long actor = jdbc.queryForObject("""
                INSERT INTO dashboard_users(login_id,password_hash,display_name)
                VALUES('aws-recheck-worker','test-only','AWS recheck worker')
                ON CONFLICT(login_id) DO UPDATE SET display_name=EXCLUDED.display_name RETURNING user_id
                """, Long.class);
        jdbc.update("UPDATE secret_connection_scopes SET response_origin='TEST',response_origin_set_by_user_id=?,response_origin_set_at=clock_timestamp() WHERE scope_id=?", actor, scopeId);
        var baseline = new FakeContentReader();
        baseline.bytes = credentialContent();
        executeContent(run(connection, scopeId), new FakeGateway(), baseline);
        var occurrence = jdbc.queryForMap("SELECT o.occurrence_id,o.credential_set_id FROM secret_occurrences o WHERE o.scope_id=?", scopeId);
        long occurrenceId = ((Number) occurrence.get("occurrence_id")).longValue();
        long credential = ((Number) occurrence.get("credential_set_id")).longValue();
        jdbc.update("UPDATE secret_occurrences SET exposure_status='ABNORMAL' WHERE occurrence_id=?", occurrenceId);
        long caseId = jdbc.queryForObject("""
                INSERT INTO secret_response_cases(credential_set_id,opening_occurrence_id,opened_by_user_id,opening_reason,
                    case_origin,review_status,action_status,version)
                VALUES(?,?,?,'ASSESSED_EXPOSURE','TEST','REVIEWED','REVALIDATION_PENDING',1) RETURNING case_id
                """, Long.class, credential, occurrenceId, actor);
        jdbc.update("INSERT INTO secret_case_occurrences(case_id,occurrence_id,credential_set_id,response_status) VALUES(?,?,?,'REVALIDATION_PENDING')", caseId, occurrenceId, credential);
        long action = jdbc.queryForObject("""
                INSERT INTO secret_action_records(case_id,occurrence_id,action_type,performed_at,recorded_by_user_id,evidence_ref,case_version)
                VALUES(?,?,'REMOVED_FROM_SOURCE',clock_timestamp()-INTERVAL '10 minutes',?,'TICKET:AWS-101',1) RETURNING action_id
                """, Long.class, caseId, occurrenceId, actor);
        jdbc.update("UPDATE secret_case_occurrences SET last_material_action_at=(SELECT performed_at FROM secret_action_records WHERE action_id=?),actions_completed_at=clock_timestamp()-INTERVAL '1 minute' WHERE case_id=?", action, caseId);
        long job = jdbc.queryForObject("""
                INSERT INTO secret_jobs(kind,connection_id,scheduled_at,available_at,attempt_no,max_attempts,status)
                VALUES('REVALIDATE',?,clock_timestamp(),clock_timestamp()-INTERVAL '1 second',0,1,'PENDING') RETURNING job_id
                """, Long.class, connection);
        long run = jdbc.queryForObject("""
                INSERT INTO secret_scan_runs(job_id,connection_id,trigger_type,scope_version,scheduled_at,requested_at,
                    collection_status,detection_status,validation_status,result_status)
                VALUES(?,?,'REVALIDATION',1,clock_timestamp(),clock_timestamp(),'PENDING','PENDING','PENDING','PENDING') RETURNING run_id
                """, Long.class, job, connection);
        jdbc.update("INSERT INTO secret_run_scopes(run_id,scope_id,collection_status) VALUES(?,?,'PENDING')", run, scopeId);
        jdbc.update("""
                INSERT INTO secret_case_revalidations(case_id,occurrence_id,action_id,connection_id,scope_id,job_id,run_id,
                    requested_by_user_id,idempotency_digest,baseline_config_hash,baseline_engine_version,baseline_fingerprint_version,
                    case_version,scope_revision,scope_origin_version,action_cycle,occurrence_version,last_material_action_at,
                    actions_completed_at,baseline_identity)
                SELECT ?,?,?,?,?,?,?,?,'aws-recheck-test',?,?,'test-v1',1,s.revision,s.response_origin_version,co.action_cycle,
                    co.version,co.last_material_action_at,co.actions_completed_at,k.fingerprint
                FROM secret_connection_scopes s JOIN secret_case_occurrences co ON co.case_id=? AND co.occurrence_id=?
                JOIN secret_credential_sets k ON k.credential_set_id=co.credential_set_id WHERE s.scope_id=?
                """, caseId, occurrenceId, action, connection, scopeId, job, run, actor,
                "a".repeat(64), "8.30.1", caseId, occurrenceId, scopeId);
        return new Recheck(caseId, occurrenceId, run);
    }

    private static byte[] credentialContent() {
        return ("AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\nAWS_SECRET_ACCESS_KEY=" + "aB3/".repeat(10) + "\n")
                .getBytes(StandardCharsets.UTF_8);
    }

    private record Recheck(long caseId, long occurrenceId, long runId) { }

    private static String exactSecretRef(String account) {
        return "aws://" + account + "/ap-northeast-2/secrets-manager/secret/"
                + "arn%3Aaws%3Asecretsmanager%3Aap-northeast-2%3A" + account
                + "%3Asecret%3Afixture-secret";
    }

    private static long contentScope(long connection, String type, String ref, int ordinal) {
        return jdbc.queryForObject("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type,
                     approved_ref, history_limit, enabled)
                VALUES (?, ?, 1, ?, ?, 'CURRENT_VALUE_ONLY', true)
                RETURNING scope_id
                """, Long.class, connection, type + "-" + ordinal, type, ref);
    }

    private static void executeContent(long run, FakeGateway gateway, FakeContentReader reader) {
        executeContent(run, gateway, reader, execution);
    }

    private static void executeContent(long run, FakeGateway gateway, FakeContentReader reader,
                                       SecretJobExecutionService executionService) {
        var processor = contentProcessor(gateway, reader, executionService);
        var job = executionService.claimNextJob("AWS").orElseThrow();
        assertThat(job.runId()).isEqualTo(run);
        processor.process(job, executionService);
        assertThat(executionService.complete(job.jobId(), job.leaseToken())).isTrue();
    }

    private static AwsSecretJobProcessor contentProcessor(FakeGateway gateway, FakeContentReader reader,
                                                          SecretJobExecutionService executionService) {
        var datasource = jdbc.getDataSource();
        var normalizer = new SecretFindingNormalizer(new byte[32], "test-v1");
        var findings = new SecretFindingRepository(jdbc,
                new TransactionTemplate(new DataSourceTransactionManager(datasource)), normalizer);
        var attempts = new SecretValidationAttemptRepository(jdbc, executionService);
        var content = new AwsContentPipeline(new AwsContentCollector(reader), new FakeDetector(),
                normalizer, findings, key -> new AwsValidationResult(AwsValidationResult.Status.UNCHECKED,
                        AwsValidationResult.Reason.DISABLED, Instant.now(), null,
                        AwsValidationResult.METHOD, AwsValidationResult.VERSION), attempts);
        return new AwsSecretJobProcessor(jdbc, new AwsIamCollector(gateway),
                new AwsMetadataCollector(new FakeMetadataPages()), gateway,
                new AwsIamMetadataRepository(jdbc, new AwsMetadataIdentity(new byte[32], "test-v1")),
                properties, "test", content);
    }

    private static final class FakeContentReader implements AwsContentReader {
        private int calls;
        private byte[] bytes = new byte[0];
        private FailureCode failure;
        private Runnable onRead;
        @Override public byte[] read(AwsContentScope scope, int maxBytes) {
            calls++;
            if (onRead != null) onRead.run();
            if (failure != null) throw new ReadFailure(failure);
            return bytes;
        }
    }

    private static final class FakeDetector implements SecretContentDetector {
        private static final String HASH = "a".repeat(64);
        @Override public String engineVersion() { return "8.30.1"; }
        @Override public String configHash() { return HASH; }
        @Override public GitleaksScanResult scan(byte[] content) {
            String text = new String(content, StandardCharsets.UTF_8);
            if (!text.contains("AWS_ACCESS_KEY_ID=")) return new GitleaksScanResult(engineVersion(), HASH, List.of());
            var findings = new java.util.ArrayList<GitleaksFinding>();
            findings.add(new GitleaksFinding("aws-access-token", 1, 1, 19, 38));
            if (text.contains("AWS_SECRET_ACCESS_KEY=") || text.contains("UNRELATED_CREDENTIAL="))
                findings.add(new GitleaksFinding("generic-api-key", 2, 2, 1, 60));
            return new GitleaksScanResult(engineVersion(), HASH, findings);
        }
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
