package com.logssey.secretworker.github;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.logssey.secretworker.SecretJobExecutionService;
import com.logssey.secretworker.SecretJobFailure;
import com.logssey.secretworker.SecretJobProperties;
import com.logssey.secretworker.SecretJobTestSupport;
import com.logssey.secretworker.detection.SecretFindingNormalizer;
import com.logssey.secretworker.detection.SecretFindingRepository;
import com.logssey.secretworker.detector.GitleaksFinding;
import com.logssey.secretworker.detector.GitleaksScanResult;
import com.logssey.secretworker.detector.SecretContentDetector;
import com.logssey.secretworker.validation.AwsValidationResult;
import com.logssey.secretworker.validation.AwsValidationService;
import com.logssey.secretworker.validation.SecretValidationAttemptRepository;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

class GitHubSecretJobProcessorTest {
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final String CONFIG_HASH = "a".repeat(64);
    private static final String COMMIT = "b".repeat(40);
    private static final String ROOT = "c".repeat(40);
    private static final String FIXTURES = "d".repeat(40);
    private static final String BLOB = "e".repeat(40);
    private static final String SECOND_BLOB = "f".repeat(40);
    private static final byte[] CONTENT = ("AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n"
            + "AWS_SECRET_ACCESS_KEY=" + "aB3/".repeat(10) + "\n").getBytes(StandardCharsets.UTF_8);
    private static JdbcTemplate jdbc;
    private static DataSourceTransactionManager transactions;

    private HttpServer server;
    private SecretJobExecutionService execution;
    private GitHubSecretJobProcessor processor;
    private GitHubCollector collector;
    private SecretContentDetector detector;
    private SecretFindingRepository findings;
    private SecretFindingNormalizer normalizer;
    private SecretValidationAttemptRepository attempts;
    private SecretJobProperties jobs;
    private String repository = "test-find-key";
    private byte[] content = CONTENT;
    private String metadataBody = "{\"private\":false,\"visibility\":\"public\"}";
    private boolean secondScope;
    private boolean secondFile;
    private boolean missingSecondBlob;
    private boolean missingPath;
    private boolean unsupportedObject;

    @BeforeAll
    static void startDatabase() {
        POSTGRES.start();
        var datasource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(),
                POSTGRES.getPassword());
        Flyway.configure().dataSource(datasource).load().migrate();
        jdbc = new JdbcTemplate(datasource);
        transactions = new DataSourceTransactionManager(datasource);
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @BeforeEach
    void setUp() throws Exception {
        jdbc.execute("TRUNCATE secret_connections RESTART IDENTITY CASCADE");
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", this::respond);
        server.start();
        var key = KeyPairGenerator.getInstance("RSA");
        key.initialize(2048);
        var api =
                new GitHubRestClient(
                        URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/"),
                        HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build());
        var token = new GitHubAppTokenProvider(123, 456, key.generateKeyPair().getPrivate(), api,
                Clock.fixed(Instant.parse("2026-10-14T00:00:00Z"), ZoneOffset.UTC));
        collector = new GitHubCollector(api, token);
        detector = new SecretContentDetector() {
            @Override public String engineVersion() { return "8.30.1"; }
            @Override public String configHash() { return CONFIG_HASH; }
            @Override public GitleaksScanResult scan(byte[] content) {
                assertThat(content).containsExactly(CONTENT);
                return new GitleaksScanResult(engineVersion(), configHash(), List.of(
                        new GitleaksFinding("aws-access-token", 1, 1, 19, 38),
                        new GitleaksFinding("generic-api-key", 2, 2, 1, 60)));
            }
        };
        normalizer = new SecretFindingNormalizer(new byte[32], "test-v1");
        findings = new SecretFindingRepository(jdbc, new TransactionTemplate(transactions), normalizer);
        jobs = new SecretJobProperties(false, Duration.ofSeconds(30), Duration.ofMinutes(5), 10,
                Duration.ofSeconds(1), Duration.ofSeconds(8));
        execution = SecretJobTestSupport.execution(jdbc, jobs, transactions);
        attempts = new SecretValidationAttemptRepository(jdbc, execution);
        processor =
                processorWith(
                        material -> {
                            throw new AssertionError("Synthetic fixture reached validator");
                        });
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    @Test
    void collectsDetectsAndPersistsOneKeyWithoutRawContent() {
        insertRun();
        jdbc.update("UPDATE secret_connection_scopes SET synthetic_fixture=true WHERE scope_key='fixtures'");
        var job = execution.claimNextJob("GITHUB").orElseThrow();
        processor.process(job, execution);
        assertThat(execution.complete(job.jobId(), job.leaseToken())).isTrue();
        assertThat(jdbc.queryForObject("SELECT result_status FROM secret_scan_runs", String.class))
                .isEqualTo("SUCCEEDED");
        assertThat(jdbc.queryForObject("SELECT object_count FROM secret_run_scopes", Long.class))
                .isEqualTo(1L);
        assertThat(
                        jdbc.queryForMap(
                                "SELECT"
                                    + " scope_revision,scope_outcome,detection_stage_status,validation_stage_status,validation_required"
                                    + " FROM secret_scope_outcomes"))
                .containsEntry("scope_revision", 1L)
                .containsEntry("scope_outcome", "SUCCEEDED")
                .containsEntry("detection_stage_status", "SUCCEEDED")
                .containsEntry("validation_stage_status", "SKIPPED")
                .containsEntry("validation_required", false);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_credential_sets", Long.class))
                .isEqualTo(1L);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_occurrences", Long.class))
                .isEqualTo(1L);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_findings", Long.class))
                .isEqualTo(2L);
        assertThat(
                        jdbc.queryForObject(
                                "SELECT validation_status FROM secret_scan_runs", String.class))
                .isEqualTo("SKIPPED");
        assertThat(
                        jdbc.queryForObject(
                                "SELECT result FROM secret_validation_attempts", String.class))
                .isEqualTo("UNCHECKED");
        assertThat(
                        jdbc.queryForObject(
                                "SELECT reason_code FROM secret_validation_attempts", String.class))
                .isEqualTo("SYNTHETIC_FIXTURE");
        String stored =
                jdbc.queryForObject(
                        "SELECT masked_label FROM secret_credential_sets", String.class);
        assertThat(stored).doesNotContain("aB3/").doesNotContain("ABCDEFGHIJKLMNOP");
    }

    @Test
    void onePairInTwoFilesHasTwoOccurrencesButOnlyOneValidationOutsideTransaction() {
        repository = "candidate-app";
        secondFile = true;
        var originalDetector = detector;
        var inspectedObjects = new AtomicInteger();
        detector = new SecretContentDetector() {
            @Override public String engineVersion() { return originalDetector.engineVersion(); }
            @Override public String configHash() { return originalDetector.configHash(); }
            @Override public GitleaksScanResult scan(byte[] value) {
                if (inspectedObjects.incrementAndGet() == 2) {
                    assertThat(jdbc.queryForObject("SELECT object_count FROM secret_run_scopes", Long.class))
                            .isEqualTo(1L);
                }
                return originalDetector.scan(value);
            }
        };
        AtomicInteger calls = new AtomicInteger();
        processor = processorWith(key -> {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            calls.incrementAndGet();
            Instant now = Instant.now();
            return new AwsValidationResult(AwsValidationResult.Status.VALID,
                    AwsValidationResult.Reason.AUTHENTICATED, now, now,
                    AwsValidationResult.METHOD, AwsValidationResult.VERSION);
        });
        insertRun();

        var job = execution.claimNextJob("GITHUB").orElseThrow();
        processor.process(job, execution);
        assertThat(execution.complete(job.jobId(), job.leaseToken())).isTrue();

        assertThat(calls).hasValue(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_credential_sets", Long.class))
                .isEqualTo(1L);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_occurrences", Long.class))
                .isEqualTo(2L);
        assertThat(
                        jdbc.queryForObject(
                                "SELECT count(*) FROM secret_validation_attempts", Long.class))
                .isEqualTo(1L);
        assertThat(jdbc.queryForObject("SELECT object_count FROM secret_run_scopes", Long.class))
                .isEqualTo(2L);
        assertThat(
                        jdbc.queryForObject(
                                "SELECT validation_status FROM secret_scan_runs", String.class))
                .isEqualTo("SUCCEEDED");
    }

    @Test
    void disabledAwsValidationPersistsUncheckedWithoutContactingSts() {
        repository = "candidate-app";
        processor = processorWith(new com.logssey.secretworker.validation.AwsCredentialValidator(false));
        insertRun();

        var job = execution.claimNextJob("GITHUB").orElseThrow();
        processor.process(job, execution);
        assertThat(execution.complete(job.jobId(), job.leaseToken())).isTrue();

        assertThat(
                        jdbc.queryForObject(
                                "SELECT result FROM secret_validation_attempts", String.class))
                .isEqualTo("UNCHECKED");
        assertThat(
                        jdbc.queryForObject(
                                "SELECT reason_code FROM secret_validation_attempts", String.class))
                .isEqualTo("DISABLED");
        assertThat(
                        jdbc.queryForObject(
                                "SELECT validation_status FROM secret_scan_runs", String.class))
                .isEqualTo("SKIPPED");
    }

    @Test
    void sourceGapKeepsEarlierFindingAndValidationWithoutMarkingOccurrenceMissing() {
        repository = "candidate-app";
        secondFile = true;
        missingSecondBlob = true;
        processor = processorWith(key -> {
            Instant now = Instant.now();
            return new AwsValidationResult(AwsValidationResult.Status.VALID,
                    AwsValidationResult.Reason.AUTHENTICATED, now, now,
                    AwsValidationResult.METHOD, AwsValidationResult.VERSION);
        });
        insertRun();

        var job = execution.claimNextJob("GITHUB").orElseThrow();
        processor.process(job, execution);
        assertThat(execution.complete(job.jobId(), job.leaseToken())).isTrue();

        assertThat(
                        jdbc.queryForObject(
                                "SELECT collection_status FROM secret_scan_runs", String.class))
                .isEqualTo("PARTIAL");
        assertThat(
                        jdbc.queryForObject(
                                "SELECT detection_status FROM secret_scan_runs", String.class))
                .isEqualTo("PARTIAL");
        assertThat(
                        jdbc.queryForObject(
                                "SELECT validation_status FROM secret_scan_runs", String.class))
                .isEqualTo("SUCCEEDED");
        assertThat(jdbc.queryForObject("SELECT result_status FROM secret_scan_runs", String.class))
                .isEqualTo("PARTIAL");
        assertThat(
                        jdbc.queryForObject(
                                "SELECT presence_status FROM secret_occurrences", String.class))
                .isEqualTo("PRESENT");
        assertThat(
                        jdbc.queryForObject(
                                "SELECT count(*) FROM secret_validation_attempts", Long.class))
                .isEqualTo(1L);
    }

    @Test
    void partialCollectionRetainsRepositoryVisibilityAndEveryGapReason() {
        repository = "candidate-app";
        secondFile = true;
        missingSecondBlob = true;
        unsupportedObject = true;
        var observed = new java.util.concurrent.atomic.AtomicReference<GitHubRepositoryAccessObservation>();
        processor = new GitHubSecretJobProcessor(jdbc, collector, detector, findings, normalizer,
                new com.logssey.secretworker.validation.AwsCredentialValidator(false), attempts, jobs,
                new com.logssey.secretworker.validation.GitHubPatValidator(false), List.of(observed::set));
        insertRun();
        var job = execution.claimNextJob("GITHUB").orElseThrow();
        processor.process(job, execution);
        assertThat(execution.complete(job.jobId(), job.leaseToken())).isTrue();
        assertThat(jdbc.queryForObject("SELECT collection_status FROM secret_run_scopes", String.class))
                .isEqualTo("PARTIAL");
        assertThat(observed.get().publicRepository()).isTrue();
        assertThat(observed.get().metadataComplete()).isTrue();
        assertThat(observed.get().occurrenceIds()).hasSize(1);
        var reasons = tools.jackson.databind.json.JsonMapper.builder().build().readTree(
                jdbc.queryForObject("SELECT exclusion_reasons::text FROM secret_run_scopes", String.class));
        assertThat(reasons.size()).isEqualTo(2);
        assertThat(reasons.path("GITHUB_UNSUPPORTED_OBJECT").asLong()).isEqualTo(1L);
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(booleans = {true, false})
    void aBlockedScopeDoesNotSuppressValidationInAnotherApprovedScope(boolean synthetic) {
        secondScope = true;
        AtomicInteger calls = new AtomicInteger();
        processor = processorWith(key -> {
            calls.incrementAndGet();
            Instant now = Instant.now();
            return new AwsValidationResult(AwsValidationResult.Status.VALID,
                    AwsValidationResult.Reason.AUTHENTICATED, now, now,
                    AwsValidationResult.METHOD, AwsValidationResult.VERSION);
        });
        insertRun();

        if (synthetic) {
            jdbc.update("UPDATE secret_connection_scopes SET synthetic_fixture=true WHERE scope_key='fixtures'");
        } else {
            jdbc.update("UPDATE secret_connection_scopes SET validation_approved=false WHERE scope_key='fixtures'");
        }

        var job = execution.claimNextJob("GITHUB").orElseThrow();
        processor.process(job, execution);
        assertThat(execution.complete(job.jobId(), job.leaseToken())).isTrue();

        assertThat(calls).hasValue(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_occurrences", Long.class))
                .isEqualTo(2L);
        assertThat(
                        jdbc.queryForObject(
                                "SELECT count(*) FROM secret_validation_attempts", Long.class))
                .isEqualTo(2L);
        assertThat(jdbc.queryForObject(
                                "SELECT count(*) FROM secret_validation_attempts WHERE result ="
                                    + " 'VALID'",
                Long.class)).isEqualTo(1L);
    }

    @Test
    void validationFailureLeavesDetectionEvidenceAndSchedulesBoundedRetryWithoutProviderMessage() {
        repository = "candidate-app";
        processor =
                processorWith(
                        key -> {
                            throw new IllegalStateException("raw " + new String(CONTENT));
                        });
        insertRun();

        var job = execution.claimNextJob("GITHUB").orElseThrow();
        assertThatThrownBy(() ->
        processor.process(job, execution)).isInstanceOf(SecretJobFailure.class);

        assertThat(
                        jdbc.queryForObject(
                                "SELECT collection_status FROM secret_scan_runs", String.class))
                .isEqualTo("SUCCEEDED");
        assertThat(
                        jdbc.queryForObject(
                                "SELECT validation_status FROM secret_scan_runs", String.class))
                .isEqualTo("PARTIAL");
        assertThat(jdbc.queryForObject("SELECT failure_code FROM secret_scan_runs", String.class))
                .isEqualTo("VALIDATION_INCONCLUSIVE");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_occurrences", Long.class))
                .isEqualTo(1L);
        assertThat(
                        jdbc.queryForObject(
                                "SELECT count(*) FROM secret_validation_attempts WHERE"
                                        + " result='UNKNOWN' AND provider_checked_at IS NULL",
                                Long.class))
                .isEqualTo(1);
        assertThat(
                        execution.fail(
                                job.jobId(),
                                job.leaseToken(),
                                com.logssey.secretworker.SecretJobFailureCode.VALIDATOR_TEMPORARY,
                                true))
                .isTrue();
        assertThat(jdbc.queryForObject(
                        "SELECT status FROM secret_jobs WHERE job_id=? AND kind='FULL_SCAN'"
                                + " AND purpose='COLLECTION_AND_DETECTION'",
                        String.class,
                        job.jobId()))
                .isEqualTo("PENDING");
    }

    private GitHubSecretJobProcessor processorWith(AwsValidationService validator) {
        return new GitHubSecretJobProcessor(jdbc, collector, detector, findings,
                normalizer, validator, attempts, jobs);
    }

    @Test
    void missingApprovedDirectoryRecordsFailureAndNeverCompletesAsEmptySuccess() {
        missingPath = true;
        insertRun();
        var job = execution.claimNextJob("GITHUB").orElseThrow();
        assertThatThrownBy(() -> processor.process(job, execution)).isInstanceOf(SecretJobFailure.class);
        assertThat(
                        jdbc.queryForObject(
                                "SELECT collection_status FROM secret_run_scopes", String.class))
                .isEqualTo("FAILED");
        assertThat(jdbc.queryForObject("SELECT object_count FROM secret_run_scopes", Long.class))
                .isZero();
        assertThat(execution.complete(job.jobId(), job.leaseToken())).isFalse();
    }

    @Test
    void changedScopeRevisionBeforeExecutionCannotReadTheNewSourceAsOldEvidence() {
        insertRun();
        jdbc.update("UPDATE secret_connection_scopes SET revision=revision+1");
        var job=execution.claimNextJob("GITHUB").orElseThrow();
        assertThatThrownBy(()->processor.process(job,execution)).isInstanceOf(SecretJobFailure.class);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_findings",Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_tool_runs", Long.class))
                .isZero();
    }

    @Test
    void changedConnectionVersionDuringDetectionCannotCommitStaleFindings() {
        insertRun();
        detector = new SecretContentDetector() {
            public String engineVersion() { return "8.30.1"; }
            public String configHash() { return CONFIG_HASH; }
            public GitleaksScanResult scan(byte[] bytes) {
                jdbc.update("UPDATE secret_connections SET scope_version=scope_version+1");
                return new GitleaksScanResult(engineVersion(), configHash(), List.of(
                        new GitleaksFinding("aws-access-token", 1, 1, 19, 38)));
            }
        };
        processor = processorWith(material -> { throw new AssertionError("Stale result reached validation"); });
        var job = execution.claimNextJob("GITHUB").orElseThrow();
        assertThatThrownBy(() -> processor.process(job, execution)).isInstanceOf(SecretJobFailure.class);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_findings", Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_occurrences", Long.class)).isZero();
    }

    @Test
    void patIsValidatedFromItsOwnMaterialAndPublishesSafeAccessEvidence() {
        String token = "ghp_" + "SENTINEL".repeat(4) + "ABCD";
        content = ("GITHUB_TOKEN=" + token + "\n").getBytes(StandardCharsets.UTF_8);
        detector =
                new SecretContentDetector() {
                    public String engineVersion() {
                        return "8.30.1";
                    }

                    public String configHash() {
                        return CONFIG_HASH;
                    }

                    public GitleaksScanResult scan(byte[] bytes) {
                        return new GitleaksScanResult(
                                engineVersion(),
                                configHash(),
                                List.of(new GitleaksFinding("github-pat", 1, 1, 14, 54)));
                    }
                };
        var pat =
                org.mockito.Mockito.mock(
                        com.logssey.secretworker.validation.GitHubPatValidator.class);
        org.mockito.Mockito.when(pat.enabled()).thenReturn(true);
        org.mockito.Mockito.when(pat.validate(token))
                .thenAnswer(
                        invocation -> {
                            assertThat(
                                            TransactionSynchronizationManager
                                                    .isActualTransactionActive())
                                    .isFalse();
                            assertThat(
                                            jdbc.queryForObject(
                                                    "SELECT attempt_state FROM"
                                                        + " secret_validation_attempts",
                                                    String.class))
                                    .isEqualTo("SENT");
                            return new com.logssey.secretworker.validation
                                    .CredentialValidationResult(
                                    "VALID", "AUTHENTICATED", Instant.now(), 200, null);
                        });
        var observed =
                new java.util.concurrent.atomic.AtomicReference<
                        GitHubRepositoryAccessObservation>();
        GitHubRepositoryAccessSink sink =
                observation -> {
                    assertThat(TransactionSynchronizationManager.isActualTransactionActive())
                            .isTrue();
                    assertThat(
                                    jdbc.queryForObject(
                                            "SELECT collection_status FROM secret_run_scopes WHERE"
                                                + " run_scope_id=?",
                                            String.class,
                                            observation.runScopeId()))
                            .isEqualTo("SUCCEEDED");
                    observed.set(observation);
                };
        processor =
                new GitHubSecretJobProcessor(
                        jdbc,
                        collector,
                        detector,
                        findings,
                        normalizer,
                        material -> {
                            throw new AssertionError("PAT sent to AWS");
                        },
                        attempts,
                        jobs,
                        pat,
                        List.of(sink));
        insertRun();
        var job = execution.claimNextJob("GITHUB").orElseThrow();
        processor.process(job, execution);
        assertThat(execution.complete(job.jobId(), job.leaseToken())).isTrue();
        org.mockito.Mockito.verify(pat).validate(token);
        assertThat(
                        jdbc.queryForMap(
                                "SELECT"
                                    + " result,endpoint_class,http_status,octet_length(source_object_version_digest)"
                                    + " AS provenance FROM secret_validation_attempts"))
                .containsEntry("result", "VALID")
                .containsEntry("endpoint_class", "GITHUB_USER")
                .containsEntry("http_status", 200)
                .containsEntry("provenance", 32);
        assertThat(
                        jdbc.queryForList(
                                        "SELECT to_jsonb(a)::text FROM secret_validation_attempts"
                                            + " a",
                                        String.class)
                                .toString())
                .doesNotContain(token, "test-token");
        assertThat(observed.get().publicRepository()).isTrue();
        assertThat(observed.get().metadataComplete()).isTrue();
        assertThat(observed.get().occurrenceIds()).hasSize(1);
        assertThat(observed.get().reasonCode()).isEqualTo("PUBLIC_CONFIRMED");
    }

    private void insertRun() {
        long connection =
                jdbc.queryForObject(
                        """
INSERT INTO secret_connections (provider, display_name, auth_ref, status, scope_version)
VALUES ('GITHUB', 'test', 'github-app-test', 'ACTIVE', 1) RETURNING connection_id
""",
                        Long.class);
        long scope =
                jdbc.queryForObject(
                        """
INSERT INTO secret_connection_scopes
    (connection_id, scope_key, revision, content_type, approved_ref, history_limit, enabled)
VALUES (?, 'fixtures', 1, 'GITHUB_REPOSITORY_FILES',
    ?, 'CURRENT_COMMIT_ONLY', true)
RETURNING scope_id
""",
                        Long.class,
                        connection,
                        "github://Logssey/" + repository + "/main/fixtures/");
        OffsetDateTime now = Instant.now().minusSeconds(1).atOffset(ZoneOffset.UTC);
        long job =
                jdbc.queryForObject(
                        """
INSERT INTO secret_jobs
    (kind, connection_id, scheduled_at, available_at, attempt_no, max_attempts, status)
VALUES ('FULL_SCAN', ?, ?, ?, 0, 3, 'PENDING') RETURNING job_id
""",
                        Long.class,
                        connection,
                        now,
                        now);
        long run =
                jdbc.queryForObject(
                        """
INSERT INTO secret_scan_runs
    (job_id, connection_id, trigger_type, scope_version, scheduled_at, requested_at,
     collection_status, detection_status, validation_status, result_status)
VALUES (?, ?, 'MANUAL', 1, ?, ?, 'PENDING', 'PENDING', 'PENDING', 'PENDING')
RETURNING run_id
""",
                        Long.class,
                        job,
                        connection,
                        now,
                        now);
        jdbc.update(
                "INSERT INTO secret_run_scopes (run_id, scope_id, collection_status) VALUES (?, ?,"
                        + " 'PENDING')",
                run, scope);
        if (secondScope) {
            long otherScope =
                    jdbc.queryForObject(
                            """
INSERT INTO secret_connection_scopes
    (connection_id, scope_key, revision, content_type, approved_ref, history_limit, enabled)
VALUES (?, 'candidate-app', 1, 'GITHUB_REPOSITORY_FILES',
    'github://Logssey/candidate-app/main/fixtures/', 'CURRENT_COMMIT_ONLY', true)
RETURNING scope_id
""",
                            Long.class,
                            connection);
            jdbc.update(
                    "INSERT INTO secret_run_scopes (run_id, scope_id, collection_status) VALUES (?,"
                        + " ?, 'PENDING')",
                    run, otherScope);
        }
        long approver =
                jdbc.queryForObject(
                        "INSERT INTO dashboard_users(login_id,password_hash,display_name,role)"
                            + " VALUES('worker-approver','h','Approver','ADMIN') ON"
                            + " CONFLICT(login_id) DO UPDATE SET display_name='Approver' RETURNING"
                            + " user_id",
                        Long.class);
        jdbc.update(
                "UPDATE secret_connections SET"
                    + " validation_enabled=true,validation_profile_version='credential-validation-v1'"
                    + " WHERE connection_id=?",
                connection);
        jdbc.update(
                "UPDATE secret_connection_scopes SET"
                    + " validation_approved=true,validation_profile_version='credential-validation-v1',validation_approved_by_user_id=?,validation_approved_at=now()"
                    + " WHERE connection_id=?",
                approver,
                connection);
    }

    private void respond(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String requestedRepository =
                secondScope && path.startsWith("/repos/Logssey/candidate-app/git/")
                        ? "candidate-app"
                        : repository;
        String prefix = "/repos/Logssey/" + requestedRepository + "/git/";
        String body;
        if (path.equals("/app/installations/456/access_tokens")) {
            String request = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String tokenRepository = secondScope && request.contains("candidate-app")
                    ? "candidate-app" : repository;
            body = "{\"token\":\"test-token\",\"permissions\":{\"contents\":\"read\"},"
                    + "\"repositories\":[{\"full_name\":\"Logssey/" + tokenRepository + "\"}]}";
        } else if (path.equals("/repos/Logssey/" + requestedRepository)) {
            body = metadataBody;
        } else if (path.equals(prefix + "ref/heads/main")) {
            body = "{\"object\":{\"type\":\"commit\",\"sha\":\"" + COMMIT + "\"}}";
        } else if (path.equals(prefix + "commits/" + COMMIT)) {
            body = "{\"tree\":{\"sha\":\"" + ROOT + "\"}}";
        } else if (path.equals(prefix + "trees/" + ROOT)) {
            body =
                    "{\"sha\":\""
                            + ROOT
                            + "\",\"tree\":"
                            + (missingPath
                                    ? "[]"
                                    : "[{\"path\":\"fixtures\","
                                            + "\"type\":\"tree\",\"mode\":\"040000\",\"sha\":\""
                                            + FIXTURES
                                            + "\"}]")
                            + "}";
        } else if (path.equals(prefix + "trees/" + FIXTURES)) {
            body =
                    "{\"sha\":\""
                            + FIXTURES
                            + "\",\"tree\":[{\"path\":\"sample.txt\","
                            + "\"type\":\"blob\",\"mode\":\"100644\",\"sha\":\""
                            + BLOB
                            + "\",\"size\":"
                            + content.length
                            + "}"
                            + (secondFile
                                    ? ", {\"path\":\"sample2.txt\",\"type\":\"blob\",\"mode\":\"100644\","
                                          + "\"sha\":\""
                                            + SECOND_BLOB
                                            + "\",\"size\":"
                                            + content.length
                                            + "}"
                                    : "")
                            + (unsupportedObject ? ", {\"path\":\"link\",\"type\":\"blob\",\"mode\":\"120000\",\"sha\":\""
                                    + SECOND_BLOB + "\",\"size\":1}" : "")
                            + "]}";
        } else if (missingSecondBlob && path.equals(prefix + "blobs/" + SECOND_BLOB)) {
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
            return;
        } else if (path.equals(prefix + "blobs/" + BLOB)
                || secondFile && path.equals(prefix + "blobs/" + SECOND_BLOB)) {
            String sha = path.endsWith(SECOND_BLOB) ? SECOND_BLOB : BLOB;
            body =
                    "{\"sha\":\""
                            + sha
                            + "\",\"encoding\":\"base64\",\"size\":"
                            + content.length
                            + ",\"content\":\""
                            + Base64.getEncoder().encodeToString(content)
                            + "\"}";
        } else {
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
            return;
        }
        byte[] response = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, response.length);
        try (var out = exchange.getResponseBody()) {
            out.write(response);
        }
    }
}
