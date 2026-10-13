package com.logssey.secretworker;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.postgresql.PostgreSQLContainer;

import com.logssey.secretworker.detection.SecretFindingNormalizer;
import com.logssey.secretworker.detection.SecretFindingRepository;
import com.logssey.secretworker.detector.GitleaksFinding;
import com.logssey.secretworker.detector.GitleaksScanResult;
import com.logssey.secretworker.validation.AwsValidationResult;
import com.logssey.secretworker.validation.SecretValidationAttemptRepository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(OutputCaptureExtension.class)
class SecretValidationAttemptRepositoryTest {
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final String CONFIG_HASH = "a".repeat(64);
    private static JdbcTemplate jdbc;
    private static DataSourceTransactionManager transactionManager;
    private SecretJobExecutionService jobs;
    private SecretFindingNormalizer normalizer;
    private SecretFindingRepository findings;
    private SecretValidationAttemptRepository attempts;
    private ClaimedSecretJob claim;
    private long runScopeId;

    @BeforeAll
    static void startDatabase() {
        POSTGRES.start();
        var datasource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(datasource).load().migrate();
        jdbc = new JdbcTemplate(datasource);
        transactionManager = new DataSourceTransactionManager(datasource);
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @BeforeEach
    void createClaimedRun() {
        jdbc.execute("TRUNCATE secret_connections RESTART IDENTITY CASCADE");
        jobs = new SecretJobExecutionService(new SecretJobRepository(jdbc),
                new SecretJobProperties(false, Duration.ofSeconds(30), Duration.ofMinutes(5),
                        10, Duration.ofSeconds(2), Duration.ofSeconds(8)), transactionManager);
        normalizer = new SecretFindingNormalizer(new byte[32], "test-v1");
        findings = new SecretFindingRepository(jdbc, new TransactionTemplate(transactionManager), normalizer);
        attempts = new SecretValidationAttemptRepository(jdbc, jobs);
        long connectionId = jdbc.queryForObject("""
                INSERT INTO secret_connections (provider, display_name, auth_ref, status, scope_version)
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
                """, Long.class, connectionId, now, now.minusSeconds(1));
        long runId = jdbc.queryForObject("""
                INSERT INTO secret_scan_runs
                    (job_id, connection_id, trigger_type, scope_version, scheduled_at,
                     requested_at, collection_status, detection_status, validation_status, result_status)
                VALUES (?, ?, 'SCHEDULED', 1, ?, ?, 'PENDING', 'PENDING', 'PENDING', 'PENDING')
                RETURNING run_id
                """, Long.class, jobId, connectionId, now, now);
        runScopeId = jdbc.queryForObject("""
                INSERT INTO secret_run_scopes (run_id, scope_id, collection_status)
                VALUES (?, ?, 'PENDING') RETURNING run_scope_id
                """, Long.class, runId, scopeId);
        claim = jobs.claimNextJob().orElseThrow();
    }

    @Test
    void storesSafeStatusAndReasonForDiscoveredAwsPairUnderLiveLease(CapturedOutput output) {
        String id = "AKIA" + "ABCDEFGHIJKLMNOP";
        String secret = "aB3/".repeat(10);
        byte[] content = ("AWS_ACCESS_KEY_ID=" + id + "\nAWS_SECRET_ACCESS_KEY=" + secret + "\n")
                .getBytes(StandardCharsets.UTF_8);
        var scan = new GitleaksScanResult("8.30.1", CONFIG_HASH, List.of(
                new GitleaksFinding("aws-access-token", 1, 1, 19, 38),
                new GitleaksFinding("generic-api-key", 2, 2, 1, 60)));
        var inspection = normalizer.inspect(claim.connectionId(), "repo/aws.txt", content, scan.findings());
        long toolRun = findings.beginGitleaksRun(runScopeId, scan.engineVersion(), scan.configHash(), Instant.now());
        assertThat(jobs.persistIfLeased(claim.jobId(), claim.leaseToken(), () ->
                findings.recordInspection(toolRun, "repo/aws.txt", "sha-1", inspection, scan, Instant.now())))
                .isTrue();
        Instant when = Instant.now().truncatedTo(ChronoUnit.MICROS);
        var result = new AwsValidationResult(AwsValidationResult.Status.VALID,
                AwsValidationResult.Reason.AUTHENTICATED, when, when,
                AwsValidationResult.METHOD, AwsValidationResult.VERSION);
        assertThat(attempts.recordIfLeased(claim.jobId(), claim.leaseToken(), claim.runId(),
                inspection.awsCandidates().getFirst().credential(), result)).isTrue();
        assertThat(jdbc.queryForMap("""
                SELECT result, reason_code, validator_id, validator_version,
                       endpoint_class, provider_checked_at IS NOT NULL AS checked
                FROM secret_validation_attempts
                """))
                .containsEntry("result", "VALID")
                .containsEntry("reason_code", "AUTHENTICATED")
                .containsEntry("validator_id", AwsValidationResult.METHOD)
                .containsEntry("validator_version", AwsValidationResult.VERSION)
                .containsEntry("endpoint_class", "AWS_STS")
                .containsEntry("checked", true);
        String persisted = jdbc.queryForList("SELECT to_jsonb(t)::text FROM secret_validation_attempts t",
                String.class).toString();
        assertThat(persisted).doesNotContain(id, secret);
        assertThat(output.getAll()).doesNotContain(id, secret);
        assertThat(attempts.recordIfLeased(claim.jobId(), "stale-lease", claim.runId(),
                inspection.awsCandidates().getFirst().credential(), result)).isFalse();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_validation_attempts", Long.class)).isEqualTo(1);
        var unknown = new AwsValidationResult(AwsValidationResult.Status.UNKNOWN,
                AwsValidationResult.Reason.CLIENT_FAILURE, when.plusSeconds(1), when.plusSeconds(1),
                AwsValidationResult.METHOD, AwsValidationResult.VERSION);
        assertThat(attempts.recordIfLeased(claim.jobId(), claim.leaseToken(), claim.runId(),
                inspection.awsCandidates().getFirst().credential(), unknown)).isTrue();
        assertThat(jdbc.queryForObject("""
                SELECT max(provider_checked_at) FROM secret_validation_attempts WHERE result = 'VALID'
                """, OffsetDateTime.class)).isEqualTo(when.atOffset(ZoneOffset.UTC));
        var invalid = new AwsValidationResult(AwsValidationResult.Status.INVALID,
                AwsValidationResult.Reason.INVALID_ACCESS_KEY, when.plusSeconds(2), when.plusSeconds(2),
                AwsValidationResult.METHOD, AwsValidationResult.VERSION);
        assertThat(attempts.recordIfLeased(claim.jobId(), claim.leaseToken(), claim.runId(),
                inspection.awsCandidates().getFirst().credential(), invalid)).isTrue();
        assertThat(jdbc.queryForList("SELECT result FROM secret_validation_attempts ORDER BY attempt_id",
                String.class)).containsExactly("VALID", "UNKNOWN", "INVALID");
    }

    @Test
    void incompleteTemporaryKeyCanOnlyBeStoredUnchecked() {
        String id = "ASIA" + "ABCDEFGHIJKLMNOP";
        byte[] content = ("AWS_ACCESS_KEY_ID=" + id + "\nAWS_SECRET_ACCESS_KEY=" + "aB3/".repeat(10) + "\n")
                .getBytes(StandardCharsets.UTF_8);
        var scan = new GitleaksScanResult("8.30.1", CONFIG_HASH, List.of(
                new GitleaksFinding("aws-access-token", 1, 1, 19, 38),
                new GitleaksFinding("generic-api-key", 2, 2, 1, 60)));
        var inspection = normalizer.inspect(claim.connectionId(), "repo/temp.env", content, scan.findings());
        long toolRun = findings.beginGitleaksRun(runScopeId, scan.engineVersion(), scan.configHash(), Instant.now());
        findings.recordInspection(toolRun, "repo/temp.env", "sha-1", inspection, scan, Instant.now());
        var candidate = inspection.awsCandidates().getFirst().credential();
        Instant when = Instant.now();
        var unchecked = new AwsValidationResult(AwsValidationResult.Status.UNCHECKED,
                AwsValidationResult.Reason.MISSING_SESSION_TOKEN, when, null,
                AwsValidationResult.METHOD, AwsValidationResult.VERSION);
        assertThat(attempts.recordIfLeased(claim.jobId(), claim.leaseToken(), claim.runId(), candidate, unchecked))
                .isTrue();
        assertThat(jdbc.queryForMap("SELECT result, reason_code, provider_checked_at FROM secret_validation_attempts"))
                .containsEntry("result", "UNCHECKED")
                .containsEntry("reason_code", "MISSING_SESSION_TOKEN")
                .containsEntry("provider_checked_at", null);
        var inventedValid = new AwsValidationResult(AwsValidationResult.Status.VALID,
                AwsValidationResult.Reason.AUTHENTICATED, when, when,
                AwsValidationResult.METHOD, AwsValidationResult.VERSION);
        assertThatThrownBy(() -> attempts.recordIfLeased(claim.jobId(), claim.leaseToken(),
                claim.runId(), candidate, inventedValid))
                .isInstanceOf(IllegalArgumentException.class).hasMessage("INVALID_VALIDATION_RESULT");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_validation_attempts", Long.class)).isEqualTo(1);
    }
}
