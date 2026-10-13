package com.logssey.secretworker.github;

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
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import com.logssey.secretworker.SecretJobExecutionService;
import com.logssey.secretworker.SecretJobFailure;
import com.logssey.secretworker.SecretJobProperties;
import com.logssey.secretworker.SecretJobTestSupport;
import com.logssey.secretworker.detection.SecretFindingNormalizer;
import com.logssey.secretworker.detection.SecretFindingRepository;
import com.logssey.secretworker.detector.GitleaksFinding;
import com.logssey.secretworker.detector.GitleaksScanResult;
import com.logssey.secretworker.detector.SecretContentDetector;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GitHubSecretJobProcessorTest {
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final String CONFIG_HASH = "a".repeat(64);
    private static final String COMMIT = "b".repeat(40);
    private static final String ROOT = "c".repeat(40);
    private static final String FIXTURES = "d".repeat(40);
    private static final String BLOB = "e".repeat(40);
    private static final byte[] CONTENT = ("AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n"
            + "AWS_SECRET_ACCESS_KEY=" + "aB3/".repeat(10) + "\n").getBytes(StandardCharsets.UTF_8);
    private static JdbcTemplate jdbc;
    private static DataSourceTransactionManager transactions;

    private HttpServer server;
    private SecretJobExecutionService execution;
    private GitHubSecretJobProcessor processor;
    private boolean missingPath;

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
        var api = new GitHubRestClient(URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/"),
                HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build());
        var token = new GitHubAppTokenProvider(123, 456, key.generateKeyPair().getPrivate(), api,
                Clock.fixed(Instant.parse("2026-10-14T00:00:00Z"), ZoneOffset.UTC));
        var collector = new GitHubCollector(api, token);
        var detector = new SecretContentDetector() {
            @Override public String engineVersion() { return "8.30.1"; }
            @Override public String configHash() { return CONFIG_HASH; }
            @Override public GitleaksScanResult scan(byte[] content) {
                assertThat(content).containsExactly(CONTENT);
                return new GitleaksScanResult(engineVersion(), configHash(), List.of(
                        new GitleaksFinding("aws-access-token", 1, 1, 19, 38),
                        new GitleaksFinding("generic-api-key", 2, 2, 1, 60)));
            }
        };
        var findings = new SecretFindingRepository(jdbc, new TransactionTemplate(transactions),
                new SecretFindingNormalizer(new byte[32], "test-v1"));
        var jobs = new SecretJobProperties(false, Duration.ofSeconds(30), Duration.ofMinutes(5), 10,
                Duration.ofSeconds(1), Duration.ofSeconds(8));
        processor = new GitHubSecretJobProcessor(jdbc, collector, detector, findings, jobs);
        execution = SecretJobTestSupport.execution(jdbc, jobs, transactions);
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    @Test
    void collectsDetectsAndPersistsOneKeyWithoutRawContent() {
        insertRun();
        var job = execution.claimNextJob("GITHUB").orElseThrow();
        processor.process(job, execution);
        assertThat(execution.complete(job.jobId(), job.leaseToken())).isTrue();
        assertThat(jdbc.queryForObject("SELECT result_status FROM secret_scan_runs", String.class))
                .isEqualTo("SUCCEEDED");
        assertThat(jdbc.queryForObject("SELECT object_count FROM secret_run_scopes", Long.class)).isEqualTo(1L);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_credential_sets", Long.class)).isEqualTo(1L);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_occurrences", Long.class)).isEqualTo(1L);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_findings", Long.class)).isEqualTo(2L);
        String stored = jdbc.queryForObject("SELECT masked_label FROM secret_credential_sets", String.class);
        assertThat(stored).doesNotContain("aB3/").doesNotContain("ABCDEFGHIJKLMNOP");
    }

    @Test
    void missingApprovedDirectoryRecordsFailureAndNeverCompletesAsEmptySuccess() {
        missingPath = true;
        insertRun();
        var job = execution.claimNextJob("GITHUB").orElseThrow();
        assertThatThrownBy(() -> processor.process(job, execution)).isInstanceOf(SecretJobFailure.class);
        assertThat(jdbc.queryForObject("SELECT collection_status FROM secret_run_scopes", String.class))
                .isEqualTo("FAILED");
        assertThat(jdbc.queryForObject("SELECT object_count FROM secret_run_scopes", Long.class)).isZero();
        assertThat(execution.complete(job.jobId(), job.leaseToken())).isFalse();
    }

    private void insertRun() {
        long connection = jdbc.queryForObject("""
                INSERT INTO secret_connections (provider, display_name, auth_ref, status, scope_version)
                VALUES ('GITHUB', 'test', 'github-app-test', 'ACTIVE', 1) RETURNING connection_id
                """, Long.class);
        long scope = jdbc.queryForObject("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref, history_limit, enabled)
                VALUES (?, 'fixtures', 1, 'GITHUB_REPOSITORY_FILES',
                    'github://Logssey/test-find-key/main/fixtures/', 'CURRENT_COMMIT_ONLY', true)
                RETURNING scope_id
                """, Long.class, connection);
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
    }

    private void respond(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
        String prefix = "/repos/Logssey/test-find-key/git/";
        String body;
        if (path.equals("/app/installations/456/access_tokens")) {
            body = "{\"token\":\"test-token\",\"permissions\":{\"contents\":\"read\"},"
                    + "\"repositories\":[{\"full_name\":\"Logssey/test-find-key\"}]}";
        } else if (path.equals(prefix + "ref/heads/main")) {
            body = "{\"object\":{\"type\":\"commit\",\"sha\":\"" + COMMIT + "\"}}";
        } else if (path.equals(prefix + "commits/" + COMMIT)) {
            body = "{\"tree\":{\"sha\":\"" + ROOT + "\"}}";
        } else if (path.equals(prefix + "trees/" + ROOT)) {
            body = "{\"sha\":\"" + ROOT + "\",\"tree\":" + (missingPath ? "[]" : "[{\"path\":\"fixtures\","
                    + "\"type\":\"tree\",\"mode\":\"040000\",\"sha\":\"" + FIXTURES + "\"}]") + "}";
        } else if (path.equals(prefix + "trees/" + FIXTURES)) {
            body = "{\"sha\":\"" + FIXTURES + "\",\"tree\":[{\"path\":\"sample.txt\","
                    + "\"type\":\"blob\",\"mode\":\"100644\",\"sha\":\"" + BLOB
                    + "\",\"size\":" + CONTENT.length + "}]}";
        } else if (path.equals(prefix + "blobs/" + BLOB)) {
            body = "{\"sha\":\"" + BLOB + "\",\"encoding\":\"base64\",\"size\":" + CONTENT.length
                    + ",\"content\":\"" + Base64.getEncoder().encodeToString(CONTENT) + "\"}";
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
