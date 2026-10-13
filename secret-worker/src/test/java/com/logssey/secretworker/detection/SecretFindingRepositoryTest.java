package com.logssey.secretworker.detection;

import java.nio.charset.StandardCharsets;
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

import com.logssey.secretworker.detector.GitleaksFinding;
import com.logssey.secretworker.detector.GitleaksScanResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecretFindingRepositoryTest {
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final String CONFIG_HASH = "a".repeat(64);
    private static JdbcTemplate jdbc;
    private SecretFindingRepository repository;
    private long runScopeId;

    @BeforeAll
    static void startDatabase() {
        POSTGRES.start();
        var datasource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(datasource).load().migrate();
        jdbc = new JdbcTemplate(datasource);
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @BeforeEach
    void createRun() {
        jdbc.execute("TRUNCATE secret_connections RESTART IDENTITY CASCADE");
        var datasource = (javax.sql.DataSource) jdbc.getDataSource();
        repository = new SecretFindingRepository(jdbc,
                new TransactionTemplate(new DataSourceTransactionManager(datasource)),
                new SecretFindingNormalizer(new byte[32], "test-v1"));
        long connectionId = jdbc.queryForObject("""
                INSERT INTO secret_connections
                    (provider, display_name, auth_ref, status, scope_version)
                VALUES ('GITHUB', 'fixture', 'test-only-ref', 'ACTIVE', 1)
                RETURNING connection_id
                """, Long.class);
        long scopeId = jdbc.queryForObject("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref, enabled)
                VALUES (?, 'fixture-scope', 1, 'TEXT', 'test-only-ref', true)
                RETURNING scope_id
                """, Long.class, connectionId);
        OffsetDateTime now = Instant.now().atOffset(ZoneOffset.UTC);
        long jobId = jdbc.queryForObject("""
                INSERT INTO secret_jobs
                    (kind, connection_id, scheduled_at, available_at, attempt_no, max_attempts, status)
                VALUES ('FULL_SCAN', ?, ?, ?, 0, 3, 'PENDING')
                RETURNING job_id
                """, Long.class, connectionId, now, now);
        long runId = jdbc.queryForObject("""
                INSERT INTO secret_scan_runs
                    (job_id, connection_id, trigger_type, scope_version, scheduled_at,
                     requested_at, collection_status, detection_status, validation_status, result_status)
                VALUES (?, ?, 'SCHEDULED', 1, ?, ?, 'RUNNING', 'RUNNING', 'PENDING', 'RUNNING')
                RETURNING run_id
                """, Long.class, jobId, connectionId, now, now);
        runScopeId = jdbc.queryForObject("""
                INSERT INTO secret_run_scopes (run_id, scope_id, collection_status)
                VALUES (?, ?, 'RUNNING') RETURNING run_scope_id
                """, Long.class, runId, scopeId);
    }

    @Test
    void persistsOneConfirmedSetAcrossTwoLocationsButKeepsCandidatesSeparate() throws Exception {
        String id = "AKIA" + "ABCDEFGHIJKLMNOP";
        String secret = "aB3/".repeat(10);
        byte[] complete = ("AWS_ACCESS_KEY_ID=" + id + "\nAWS_SECRET_ACCESS_KEY=" + secret + "\n")
                .getBytes(StandardCharsets.UTF_8);
        byte[] incomplete = ("AWS_ACCESS_KEY_ID=" + id + "\n").getBytes(StandardCharsets.UTF_8);
        var pairScan = new GitleaksScanResult("8.30.1", CONFIG_HASH, List.of(
                new GitleaksFinding("aws-access-token", 1, 1, 19, 38),
                new GitleaksFinding("generic-api-key", 2, 2, 1, 60)));
        var idScan = new GitleaksScanResult("8.30.1", CONFIG_HASH,
                List.of(new GitleaksFinding("aws-access-token", 1, 1, 19, 38)));
        long toolRunId = repository.beginGitleaksRun(runScopeId, "8.30.1", CONFIG_HASH, Instant.now());
        assertThat(repository.beginGitleaksRun(runScopeId, "8.30.1", CONFIG_HASH, Instant.now()))
                .isEqualTo(toolRunId);
        repository.recordObject(toolRunId, "repo/first.txt", "sha-1", complete, pairScan, Instant.now());
        repository.recordObject(toolRunId, "repo/second.txt", "sha-2", complete, pairScan, Instant.now());
        repository.recordObject(toolRunId, "repo/incomplete-a.txt", "sha-3", incomplete, idScan, Instant.now());
        repository.recordObject(toolRunId, "repo/incomplete-b.txt", "sha-4", incomplete, idScan, Instant.now());
        repository.recordObject(toolRunId, "repo/first.txt", "sha-1", complete, pairScan, Instant.now());
        assertThat(repository.recordObject(toolRunId, "repo/empty.txt", "sha-5", new byte[0],
                new GitleaksScanResult("8.30.1", CONFIG_HASH, List.of()), Instant.now()))
                .isEqualTo(new SecretFindingRepository.ObjectResult(0, 0));
        repository.finishToolRun(toolRunId, "SUCCEEDED", null, Instant.now());

        assertThat(count("secret_credential_sets")).isEqualTo(3);
        assertThat(count("secret_occurrences")).isEqualTo(4);
        assertThat(count("secret_findings")).isEqualTo(6);
        assertThat(jdbc.queryForObject("SELECT finding_count FROM secret_tool_runs", Long.class)).isEqualTo(6);
        assertThat(jdbc.queryForObject("""
                SELECT count(*) FROM secret_occurrences o
                JOIN secret_credential_sets c USING (credential_set_id)
                WHERE c.component_state = 'CONFIRMED'
                """, Long.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("""
                SELECT count(*) FROM secret_credential_sets
                WHERE component_state = 'CANDIDATE' AND fingerprint IS NULL
                """, Long.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT issuer FROM secret_credential_sets WHERE component_state='CONFIRMED'",
                String.class)).isEqualTo("AWS");
        String persisted = String.join("\n", List.of(
                jdbc.queryForList("SELECT to_jsonb(t)::text FROM secret_credential_sets t", String.class).toString(),
                jdbc.queryForList("SELECT to_jsonb(t)::text FROM secret_occurrences t", String.class).toString(),
                jdbc.queryForList("SELECT to_jsonb(t)::text FROM secret_findings t", String.class).toString(),
                jdbc.queryForList("SELECT to_jsonb(t)::text FROM secret_tool_runs t", String.class).toString()));
        assertThat(persisted).doesNotContain(id, secret);
    }

    @Test
    void rejectsMismatchedDetectorConfigurationBeforeWritingAnything() {
        long toolRunId = repository.beginGitleaksRun(runScopeId, "8.30.1", CONFIG_HASH, Instant.now());
        var mismatched = new GitleaksScanResult("8.30.2", CONFIG_HASH, List.of());
        assertThatThrownBy(() -> repository.recordObject(toolRunId, "repo/file.txt", null,
                new byte[0], mismatched, Instant.now()))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("TOOL_RUN_RESULT_MISMATCH");
        assertThat(count("secret_credential_sets")).isZero();
        assertThat(count("secret_findings")).isZero();
    }

    @Test
    void rejectsInspectionForAnotherSourceBeforeWritingAnything() {
        long connectionId = jdbc.queryForObject("SELECT connection_id FROM secret_connections", Long.class);
        var scan = new GitleaksScanResult("8.30.1", CONFIG_HASH,
                List.of(new GitleaksFinding("aws-access-token", 1, 1, 19, 38)));
        byte[] content = ("AWS_ACCESS_KEY_ID=" + "AKIAABCDEFGHIJKLMNOP" + "\n")
                .getBytes(StandardCharsets.UTF_8);
        var inspection = new SecretFindingNormalizer(new byte[32], "test-v1")
                .inspect(connectionId, "repo/other.txt", content, scan.findings());
        long toolRunId = repository.beginGitleaksRun(runScopeId, "8.30.1", CONFIG_HASH, Instant.now());
        assertThatThrownBy(() -> repository.recordInspection(toolRunId, "repo/file.txt", "sha-1",
                inspection, scan, Instant.now()))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("INSPECTION_SCOPE_MISMATCH");
        assertThat(count("secret_credential_sets")).isZero();
        assertThat(count("secret_findings")).isZero();
    }

    @Test
    void retryDropsEarlierToolFindingsAndMarksTheirOnlyOccurrenceUnknown() {
        String id = "AKIA" + "ABCDEFGHIJKLMNOP";
        byte[] content = ("AWS_ACCESS_KEY_ID=" + id + "\n").getBytes(StandardCharsets.UTF_8);
        var scan = new GitleaksScanResult("8.30.1", CONFIG_HASH,
                List.of(new GitleaksFinding("aws-access-token", 1, 1, 19, 38)));
        long toolRunId = repository.beginGitleaksRun(runScopeId, "8.30.1", CONFIG_HASH, Instant.now());
        repository.recordObject(toolRunId, "repo/partial.txt", "sha-1", content, scan, Instant.now());
        repository.finishToolRun(toolRunId, "FAILED", "SOURCE_UNAVAILABLE", Instant.now());
        assertThat(count("secret_findings")).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT presence_status FROM secret_occurrences", String.class))
                .isEqualTo("PRESENT");

        assertThat(repository.beginGitleaksRun(runScopeId, "8.30.1", CONFIG_HASH, Instant.now()))
                .isEqualTo(toolRunId);
        assertThat(count("secret_findings")).isZero();
        assertThat(jdbc.queryForObject("SELECT presence_status FROM secret_occurrences", String.class))
                .isEqualTo("UNKNOWN");
        repository.recordObject(toolRunId, "repo/partial.txt", "sha-2", content, scan, Instant.now());
        assertThat(jdbc.queryForObject("SELECT presence_status FROM secret_occurrences", String.class))
                .isEqualTo("PRESENT");
        assertThat(count("secret_findings")).isEqualTo(1);
        repository.finishToolRun(toolRunId, "SUCCEEDED", null, Instant.now());
        repository.beginGitleaksRun(runScopeId, "8.30.1", CONFIG_HASH, Instant.now());
        assertThat(count("secret_findings")).isZero();
        assertThat(jdbc.queryForObject("SELECT presence_status FROM secret_occurrences", String.class))
                .isEqualTo("UNKNOWN");
    }

    private static long count(String table) {
        return jdbc.queryForObject("SELECT count(*) FROM " + table, Long.class);
    }
}
