package com.logssey.secretworker.notion;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.logssey.secretworker.SecretJobExecutionService;
import com.logssey.secretworker.SecretJobFailure;
import com.logssey.secretworker.SecretJobProperties;
import com.logssey.secretworker.SecretJobTestSupport;
import com.logssey.secretworker.assessment.NotionRiskObservationSink;
import com.logssey.secretworker.detection.SecretFindingNormalizer;
import com.logssey.secretworker.detection.SecretFindingRepository;
import com.logssey.secretworker.detector.GitleaksFinding;
import com.logssey.secretworker.detector.GitleaksScanResult;
import com.logssey.secretworker.detector.SecretContentDetector;
import com.logssey.secretworker.validation.CredentialValidationResult;
import com.logssey.secretworker.validation.GitHubPatValidator;
import com.logssey.secretworker.validation.NotionTokenValidator;
import com.logssey.secretworker.validation.SecretValidationAttemptRepository;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
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

/** Notion is mimicked by a local server; every token here is synthetic. */
class NotionSecretJobProcessorTest {
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final String CONFIG_HASH = "a".repeat(64);
    private static final String PAGE = "0123456789abcdef0123456789abcdef";
    private static final String PAGE_ID = "01234567-89ab-cdef-0123-456789abcdef";
    private static final String FOUND = "ntn_" + "12345678901" + "SENTINEL".repeat(4) + "XYZ";
    private static final String COLLECTOR = "ntn_" + "98765432109" + "COLLECTOR".repeat(3) + "ABCDEFGH";
    private static JdbcTemplate jdbc;
    private static DataSourceTransactionManager transactions;

    private HttpServer server;
    private SecretJobExecutionService execution;
    private SecretFindingRepository findings;
    private SecretFindingNormalizer normalizer;
    private SecretValidationAttemptRepository attempts;
    private SecretJobProperties jobs;
    private NotionPageClient client;
    private SecretContentDetector detector;
    private String markdown = "NOTION_TOKEN=" + FOUND;
    private List<GitleaksFinding> detected = List.of(new GitleaksFinding("notion-api-token", 1, 1, 14, 63));
    private int pageStatus = 200;
    private boolean published = true;
    private boolean trashed;
    private boolean truncated;
    private final AtomicInteger notionCalls = new AtomicInteger();

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
        client = new NotionPageClient(URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/"),
                HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build(), () -> COLLECTOR);
        detector = new SecretContentDetector() {
            @Override public String engineVersion() { return "8.30.1"; }
            @Override public String configHash() { return CONFIG_HASH; }
            @Override public GitleaksScanResult scan(byte[] content) {
                assertThat(new String(content, StandardCharsets.UTF_8)).isEqualTo(markdown);
                return new GitleaksScanResult(engineVersion(), configHash(), detected);
            }
        };
        normalizer = new SecretFindingNormalizer(new byte[32], "test-v1");
        findings = new SecretFindingRepository(jdbc, new TransactionTemplate(transactions), normalizer);
        jobs = new SecretJobProperties(false, Duration.ofSeconds(30), Duration.ofMinutes(5), 10,
                Duration.ofSeconds(1), Duration.ofSeconds(8));
        execution = SecretJobTestSupport.execution(jdbc, jobs, transactions);
        attempts = new SecretValidationAttemptRepository(jdbc, execution);
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    @Test
    void findsTheTokenStoresOnlySafeMetadataValidatesOutsideTransactionsAndRecordsWebPublication() {
        var notion = org.mockito.Mockito.mock(NotionTokenValidator.class);
        org.mockito.Mockito.when(notion.enabled()).thenReturn(true);
        org.mockito.Mockito.when(notion.validate(FOUND)).thenAnswer(invocation -> {
            assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
            return new CredentialValidationResult("VALID", "AUTHENTICATED", Instant.now(), 200, null);
        });
        var observed = new AtomicReference<NotionPageAccessObservation>();
        var realSink = new NotionRiskObservationSink(jdbc);
        NotionPageAccessSink sink = observation -> {
            observed.set(observation);
            realSink.observe(observation);
        };
        insertRun();
        var job = execution.claimNextJob("NOTION").orElseThrow();
        processor(notion, List.of(sink)).process(job, execution);
        assertThat(execution.complete(job.jobId(), job.leaseToken())).isTrue();

        org.mockito.Mockito.verify(notion).validate(FOUND);
        assertThat(jdbc.queryForObject("SELECT result_status FROM secret_scan_runs", String.class))
                .isEqualTo("SUCCEEDED");
        assertThat(jdbc.queryForMap("SELECT issuer,credential_type,component_state,masked_label FROM secret_credential_sets"))
                .containsEntry("issuer", "NOTION")
                .containsEntry("credential_type", "NOTION_CONNECTION_TOKEN")
                .containsEntry("component_state", "CONFIRMED");
        assertThat(jdbc.queryForObject("SELECT source_object_ref FROM secret_occurrences", String.class))
                .isEqualTo("notion/pages/" + PAGE_ID);
        assertThat(jdbc.queryForMap("SELECT result,reason_code,validator_id,endpoint_class FROM secret_validation_attempts"))
                .containsEntry("result", "VALID")
                .containsEntry("reason_code", "AUTHENTICATED")
                .containsEntry("validator_id", NotionTokenValidator.METHOD)
                .containsEntry("endpoint_class", NotionTokenValidator.ENDPOINT_CLASS);
        assertThat(observed.get().publishedToWeb()).isTrue();
        assertThat(observed.get().occurrenceIds()).hasSize(1);
        assertThat(jdbc.queryForMap(
                "SELECT kind,writer_service_id,reason_code,safe_payload->>'audienceClass' AS audience"
                        + " FROM secret_risk_evidence"))
                .containsEntry("kind", "ACCESS_SCOPE")
                .containsEntry("writer_service_id", "NOTION_PAGE_METADATA_V1")
                .containsEntry("reason_code", "PUBLISHED_TO_WEB_CONFIRMED")
                .containsEntry("audience", "BROAD");
        String everything = "" + jdbc.queryForList("SELECT to_jsonb(k)::text FROM secret_credential_sets k", String.class)
                + jdbc.queryForList("SELECT to_jsonb(a)::text FROM secret_validation_attempts a", String.class)
                + jdbc.queryForList("SELECT to_jsonb(f)::text FROM secret_findings f", String.class)
                + jdbc.queryForList("SELECT to_jsonb(e)::text FROM secret_risk_evidence e", String.class);
        assertThat(everything).doesNotContain(FOUND).doesNotContain(COLLECTOR).doesNotContain("SENTINEL");
    }

    @Test
    void unpublishedPageDoesNotClaimALimitedAudience() {
        published = false;
        insertRun();
        var job = execution.claimNextJob("NOTION").orElseThrow();
        processor(new NotionTokenValidator(false), List.of(new NotionRiskObservationSink(jdbc))).process(job, execution);
        assertThat(execution.complete(job.jobId(), job.leaseToken())).isTrue();
        assertThat(jdbc.queryForMap("SELECT reason_code,safe_payload->>'audienceClass' AS audience FROM secret_risk_evidence"))
                .containsEntry("reason_code", "ACCESS_RANGE_NOT_PROVEN")
                .containsEntry("audience", "UNKNOWN");
        assertThat(jdbc.queryForMap("SELECT result,reason_code FROM secret_validation_attempts"))
                .containsEntry("result", "UNCHECKED")
                .containsEntry("reason_code", "DISABLED");
    }

    @Test
    void tokenWrittenInKoreanProseIsReportedAsAGapInsteadOfAnEmptyPage() {
        // Known limit of the shared normalizer: only "NAME=value" style lines are attributed.
        markdown = "노션 토큰: " + FOUND;
        detected = List.of(new GitleaksFinding("notion-api-token", 1, 1, 8, 57));
        insertRun();
        var job = execution.claimNextJob("NOTION").orElseThrow();
        processor(new NotionTokenValidator(false), List.of()).process(job, execution);
        assertThat(execution.complete(job.jobId(), job.leaseToken())).isTrue();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_credential_sets", Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT failure_code FROM secret_run_scopes", String.class))
                .isEqualTo("NOTION_UNATTRIBUTED_FINDINGS");
        assertThat(jdbc.queryForObject("SELECT result_status FROM secret_scan_runs", String.class))
                .isEqualTo("PARTIAL");
    }

    @Test
    void pageNotSharedWithTheCollectorFailsWithoutLookingLikeAnEmptySuccess() {
        pageStatus = 404;
        insertRun();
        var job = execution.claimNextJob("NOTION").orElseThrow();
        assertThatThrownBy(() -> processor(new NotionTokenValidator(false), List.of()).process(job, execution))
                .isInstanceOf(SecretJobFailure.class)
                .satisfies(e -> assertThat(((SecretJobFailure) e).retryable()).isFalse());
        assertThat(jdbc.queryForMap("SELECT collection_status,failure_code,object_count FROM secret_run_scopes"))
                .containsEntry("collection_status", "FAILED")
                .containsEntry("failure_code", "NOTION_NOT_FOUND")
                .containsEntry("object_count", 0L);
        assertThat(execution.complete(job.jobId(), job.leaseToken())).isFalse();
    }

    @Test
    void trashedPageIsNotReadAndIsRecordedAsFailed() {
        trashed = true;
        insertRun();
        var job = execution.claimNextJob("NOTION").orElseThrow();
        assertThatThrownBy(() -> processor(new NotionTokenValidator(false), List.of()).process(job, execution))
                .isInstanceOf(SecretJobFailure.class);
        assertThat(jdbc.queryForObject("SELECT failure_code FROM secret_run_scopes", String.class))
                .isEqualTo("NOTION_PAGE_TRASHED");
        assertThat(notionCalls).hasValue(1);
    }

    @Test
    void truncatedPageKeepsFindingsButIsPartial() {
        truncated = true;
        insertRun();
        var job = execution.claimNextJob("NOTION").orElseThrow();
        processor(new NotionTokenValidator(false), List.of()).process(job, execution);
        assertThat(execution.complete(job.jobId(), job.leaseToken())).isTrue();
        assertThat(jdbc.queryForObject("SELECT collection_status FROM secret_scan_runs", String.class))
                .isEqualTo("PARTIAL");
        assertThat(jdbc.queryForObject("SELECT failure_code FROM secret_run_scopes", String.class))
                .isEqualTo("NOTION_CONTENT_TRUNCATED");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_credential_sets", Long.class)).isEqualTo(1L);
    }

    private NotionSecretJobProcessor processor(NotionTokenValidator notion, List<NotionPageAccessSink> sinks) {
        return new NotionSecretJobProcessor(jdbc, client, detector, findings, normalizer,
                material -> {
                    throw new AssertionError("Notion page content reached AWS");
                },
                attempts, jobs, new GitHubPatValidator(false), notion, sinks);
    }

    private void respond(HttpExchange exchange) throws IOException {
        notionCalls.incrementAndGet();
        assertThat(exchange.getRequestHeaders().getFirst("Authorization")).isEqualTo("Bearer " + COLLECTOR);
        String path = exchange.getRequestURI().getPath();
        int status = pageStatus;
        String body;
        if (path.equals("/v1/pages/" + PAGE_ID)) {
            body = "{\"object\":\"page\",\"id\":\"" + PAGE_ID + "\",\"last_edited_time\":\"2026-11-02T00:00:00.000Z\","
                    + "\"in_trash\":" + trashed + ",\"public_url\":"
                    + (published ? "\"https://example.notion.site/test\"" : "null") + "}";
        } else if (path.equals("/v1/pages/" + PAGE_ID + "/markdown")) {
            body = "{\"object\":\"page_markdown\",\"markdown\":" + quote(markdown) + ",\"truncated\":" + truncated + "}";
        } else {
            status = 404;
            body = "{}";
        }
        if (status != 200) body = "{\"object\":\"error\",\"status\":" + status + "}";
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        exchange.getResponseBody().write(bytes);
        exchange.close();
    }

    private static String quote(String value) {
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private void insertRun() {
        long connection = jdbc.queryForObject("""
INSERT INTO secret_connections (provider, display_name, auth_ref, status, scope_version)
VALUES ('NOTION', 'test', 'notion-connection:test', 'ACTIVE', 1) RETURNING connection_id
""", Long.class);
        long scope = jdbc.queryForObject("""
INSERT INTO secret_connection_scopes
    (connection_id, scope_key, revision, content_type, approved_ref, history_limit, enabled)
VALUES (?, 'notion:page', 1, 'NOTION_PAGE_CONTENT', ?, 'CURRENT_VERSION_ONLY', true)
RETURNING scope_id
""", Long.class, connection, "notion://pages/" + PAGE);
        OffsetDateTime now = Instant.now().minusSeconds(1).atOffset(ZoneOffset.UTC);
        long job = jdbc.queryForObject("""
INSERT INTO secret_jobs
    (kind, connection_id, scheduled_at, available_at, attempt_no, max_attempts, status)
VALUES ('FULL_SCAN', ?, ?, ?, 0, 3, 'PENDING') RETURNING job_id
""", Long.class, connection, now, now);
        long run = jdbc.queryForObject("""
INSERT INTO secret_scan_runs
    (job_id, connection_id, trigger_type, scope_version, scheduled_at, requested_at,
     collection_status, detection_status, validation_status, result_status)
VALUES (?, ?, 'MANUAL', 1, ?, ?, 'PENDING', 'PENDING', 'PENDING', 'PENDING')
RETURNING run_id
""", Long.class, job, connection, now, now);
        jdbc.update("INSERT INTO secret_run_scopes (run_id, scope_id, collection_status) VALUES (?, ?, 'PENDING')",
                run, scope);
        long approver = jdbc.queryForObject(
                "INSERT INTO dashboard_users(login_id,password_hash,display_name,role)"
                        + " VALUES('worker-approver','h','Approver','ADMIN') ON"
                        + " CONFLICT(login_id) DO UPDATE SET display_name='Approver' RETURNING user_id",
                Long.class);
        jdbc.update("UPDATE secret_connections SET validation_enabled=true,"
                + "validation_profile_version='credential-validation-v1' WHERE connection_id=?", connection);
        jdbc.update("UPDATE secret_connection_scopes SET validation_approved=true,"
                + "validation_profile_version='credential-validation-v1',validation_approved_by_user_id=?,"
                + "validation_approved_at=now() WHERE connection_id=?", approver, connection);
    }
}
