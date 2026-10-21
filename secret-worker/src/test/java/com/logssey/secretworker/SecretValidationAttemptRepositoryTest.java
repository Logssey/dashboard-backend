package com.logssey.secretworker;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import com.logssey.secretworker.detection.SecretFindingNormalizer;
import com.logssey.secretworker.detection.SecretFindingRepository;
import com.logssey.secretworker.detector.GitleaksFinding;
import com.logssey.secretworker.detector.GitleaksScanResult;
import com.logssey.secretworker.detector.SecretContentDetector;
import com.logssey.secretworker.validation.AwsValidationResult;
import com.logssey.secretworker.validation.AwsValidationService;
import com.logssey.secretworker.validation.CredentialRevalidationProcessor;
import com.logssey.secretworker.validation.SecretValidationAttemptRepository;

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

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;

import java.util.List;

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
        assertThat(jdbc.queryForMap(
                                "SELECT result, reason_code, provider_checked_at FROM"
                                    + " secret_validation_attempts"))
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

    @Test
    void reservesAndFencesBeforeCallingAwsOutsideTheTransaction(CapturedOutput output) {
        var candidate = discovered();
        approve();
        var calls = new java.util.concurrent.atomic.AtomicInteger();
        AwsValidationService provider =
                material -> {
                    calls.incrementAndGet();
                    assertThat(
                                    org.springframework.transaction.support
                                            .TransactionSynchronizationManager
                                            .isActualTransactionActive())
                            .isFalse();
                    assertThat(
                                    jdbc.queryForObject(
                                            "SELECT attempt_state FROM secret_validation_attempts",
                                            String.class))
                            .isEqualTo("SENT");
                    return checked(
                            AwsValidationResult.Status.VALID,
                            AwsValidationResult.Reason.AUTHENTICATED,
                            Instant.now());
};
        assertThat(
                        attempts.validateAws(
                                        claim,
                                        candidate.credential(),
                                        candidate.material(),
                                        false,
                                        provider)
                                .status())
                .isEqualTo(AwsValidationResult.Status.VALID);
        attempts.validateAws(claim, candidate.credential(), candidate.material(), false, provider);
        assertThat(calls).hasValue(1);
        assertThat(
                        jdbc.queryForObject(
                                "SELECT count(*) FROM secret_current_validation_attempts",
                                Long.class))
                .isEqualTo(1);
        assertThat(
                        jdbc.queryForObject(
                                "SELECT current_eligible FROM secret_validation_attempts",
                                Boolean.class))
                .isTrue();
        assertThat(
                        jdbc.queryForList(
                                        "SELECT to_jsonb(a)::text FROM secret_validation_attempts"
                                            + " a",
                                        String.class)
                                .toString())
                .doesNotContain("AKIAABCDEFGHIJKLMNOP", "aB3/".repeat(10));
        assertThat(output.getAll()).doesNotContain("AKIAABCDEFGHIJKLMNOP", "aB3/".repeat(10));
    }

    @Test
    void approvalRevokedDuringProviderResponsePreservesOnlyHistoricalResult() {
        var candidate = discovered();
        approve();
        attempts.validateAws(
                claim,
                candidate.credential(),
                candidate.material(),
                false,
                material -> {
                    jdbc.update(
                            "UPDATE secret_connection_scopes SET"
                                + " validation_approved=false,validation_approval_revision=validation_approval_revision+1");
                    return checked(
                            AwsValidationResult.Status.VALID,
                            AwsValidationResult.Reason.AUTHENTICATED,
                            Instant.now());
                });
        assertThat(
                        jdbc.queryForMap(
                                "SELECT result,current_eligible,ineligible_reason_code FROM"
                                        + " secret_validation_attempts"))
                .containsEntry("result", "VALID")
                .containsEntry("current_eligible", false)
                .containsEntry("ineligible_reason_code", "APPROVAL_CHANGED");
        assertThat(
                        jdbc.queryForObject(
                                "SELECT count(*) FROM secret_current_validation_attempts",
                                Long.class))
                .isZero();
    }

    @Test
    void timeoutHasSentAndCompletionTimesButNoInventedProviderObservation() {
        var candidate = discovered();
        approve();
        var result =
                attempts.validateAws(
                        claim,
                        candidate.credential(),
                        candidate.material(),
                        false,
                        material -> {
                            throw new IllegalStateException("SENTINEL_PROVIDER_EXCEPTION");
                        });
        assertThat(result.status()).isEqualTo(AwsValidationResult.Status.UNKNOWN);
        assertThat(
                        jdbc.queryForMap(
                                "SELECT request_sent_at IS NOT NULL AS sent,completed_at IS NOT"
                                    + " NULL AS completed,provider_checked_at FROM"
                                    + " secret_validation_attempts"))
                .containsEntry("sent", true)
                .containsEntry("completed", true)
                .containsEntry("provider_checked_at", null);
    }

    @Test
    void syntheticSourceAndDisabledProfileNeverInvokeProvider() {
        jdbc.update("UPDATE secret_connection_scopes SET synthetic_fixture=true WHERE scope_id=(SELECT scope_id FROM secret_run_scopes WHERE run_scope_id=?)", runScopeId);
        var candidate = discovered();
        var calls = new java.util.concurrent.atomic.AtomicInteger();
        var result =
                attempts.validateAws(
                        claim,
                        candidate.credential(),
                        candidate.material(),
                        true,
                        material -> {
                            calls.incrementAndGet();
                            return checked(
                                    AwsValidationResult.Status.VALID,
                                    AwsValidationResult.Reason.AUTHENTICATED,
                                    Instant.now());
                        });
        assertThat(result.reason()).isEqualTo(AwsValidationResult.Reason.SYNTHETIC_FIXTURE);
        assertThat(calls).hasValue(0);
        assertThat(
                        jdbc.queryForObject(
                                "SELECT request_sent_at FROM secret_validation_attempts",
                                OffsetDateTime.class))
                .isNull();
    }

    @Test
    void manualReacquisitionReservesBeforeReadAndNeverChangesPresence() {
        discovered();
        approve();
        manual();
        var calls = new java.util.concurrent.atomic.AtomicInteger();
        var processor =
                new CredentialRevalidationProcessor(
                        jdbc,
                        normalizer,
                        testDetector(),
                        attempts,
                        material -> {
                            calls.incrementAndGet();
                            return checked(
                                    AwsValidationResult.Status.VALID,
                                    AwsValidationResult.Reason.AUTHENTICATED,
                                    Instant.now());
                        });
        processor.process(
                claim,
                jobs,
                (target, sink) -> {
                    assertThat(
                                    jdbc.queryForObject(
                                            "SELECT attempt_state FROM secret_validation_attempts",
                                            String.class))
                            .isEqualTo("RESERVED");
                    sink.accept("repo/aws.txt", "current-blob", source("aB3/".repeat(10)));
                    return true;
                });
        assertThat(calls).hasValue(1);
        assertThat(jobs.complete(claim.jobId(), claim.leaseToken())).isTrue();
        assertThat(
                        jdbc.queryForObject(
                                "SELECT presence_status FROM secret_occurrences", String.class))
                .isEqualTo("PRESENT");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_findings", Long.class))
                .isEqualTo(2);
        assertThat(
                        jdbc.queryForObject(
                                "SELECT result FROM secret_current_validation_attempts",
                                String.class))
                .isEqualTo("VALID");
    }

    @Test
    void replacedSourceValueCannotValidateTheOldCredential() {
        discovered();
        approve();
        manual();
        var calls = new java.util.concurrent.atomic.AtomicInteger();
        var processor =
                new CredentialRevalidationProcessor(
                        jdbc,
                        normalizer,
                        testDetector(),
                        attempts,
                        material -> {
                            calls.incrementAndGet();
                            return checked(
                                    AwsValidationResult.Status.VALID,
                                    AwsValidationResult.Reason.AUTHENTICATED,
                                    Instant.now());
                        });
        processor.process(
                claim,
                jobs,
                (target, sink) -> {
                    sink.accept("repo/aws.txt", "changed-blob", source("zB3/".repeat(10)));
                    return true;
                });
        assertThat(calls).hasValue(0);
        assertThat(
                        jdbc.queryForMap(
                                "SELECT result,reason_code,request_sent_at,provider_checked_at FROM"
                                        + " secret_validation_attempts"))
                .containsEntry("result", "UNKNOWN")
                .containsEntry("reason_code", "CREDENTIAL_MISMATCH")
                .containsEntry("request_sent_at", null)
                .containsEntry("provider_checked_at", null);
        assertThat(
                        jdbc.queryForObject(
                                "SELECT presence_status FROM secret_occurrences", String.class))
                .isEqualTo("PRESENT");
    }

    private void manual() {
        long actor =
                jdbc.queryForObject(
                        "SELECT user_id FROM dashboard_users WHERE login_id='validation-approver'",
                        Long.class);
        jdbc.update(
                "INSERT INTO"
                    + " secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source)"
                    + " VALUES(?,'SECURITY',?,?,'MANUAL') ON CONFLICT DO NOTHING",
                actor,
                claim.connectionId(),
                actor);
        jdbc.update(
                "UPDATE secret_jobs SET"
                    + " kind='REVALIDATE',purpose='CREDENTIAL_VALIDITY',requested_by_user_id=?,target_occurrence_id=(SELECT"
                    + " occurrence_id FROM secret_occurrences LIMIT"
                    + " 1),expected_context=jsonb_build_object('contextVersion',(SELECT"
                    + " context_version FROM secret_validation_context LIMIT 1)) WHERE job_id=?",
                actor,
                claim.jobId());
    }

    private static byte[] source(String secret) {
        return ("AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\nAWS_SECRET_ACCESS_KEY=" + secret + "\n")
                .getBytes(StandardCharsets.UTF_8);
    }

    private static SecretContentDetector testDetector() {
        return new SecretContentDetector() {
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
                        List.of(
                                new GitleaksFinding("aws-access-token", 1, 1, 19, 38),
                                new GitleaksFinding("generic-api-key", 2, 2, 1, 60)));
            }
        };
    }

    private SecretFindingNormalizer.AwsCandidate discovered() {
        byte[] content =
                ("AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\nAWS_SECRET_ACCESS_KEY="
                                + "aB3/".repeat(10)
                                + "\n")
                        .getBytes(StandardCharsets.UTF_8);
        var scan =
                new GitleaksScanResult(
                        "8.30.1",
                        CONFIG_HASH,
                        List.of(
                                new GitleaksFinding("aws-access-token", 1, 1, 19, 38),
                                new GitleaksFinding("generic-api-key", 2, 2, 1, 60)));
        var inspected =
                normalizer.inspect(claim.connectionId(), "repo/aws.txt", content, scan.findings());
        long tool =
                findings.beginGitleaksRun(
                        runScopeId, scan.engineVersion(), scan.configHash(), Instant.now());
        findings.recordInspection(tool, "repo/aws.txt", "sha-1", inspected, scan, Instant.now());
        return inspected.awsCandidates().getFirst();
    }

    private void approve() {
        long actor =
                jdbc.queryForObject(
                        "INSERT INTO dashboard_users(login_id,password_hash,display_name,role)"
                            + " VALUES('validation-approver','h','Approver','ADMIN') ON"
                            + " CONFLICT(login_id) DO UPDATE SET display_name='Approver' RETURNING"
                            + " user_id",
                        Long.class);
        jdbc.update(
                "UPDATE secret_connections SET"
                    + " validation_enabled=true,validation_profile_version='credential-validation-v1'");
        jdbc.update(
                "UPDATE secret_connection_scopes SET"
                    + " validation_approved=true,validation_profile_version='credential-validation-v1',validation_approved_by_user_id=?,validation_approved_at=now()",
                actor);
    }

    private static AwsValidationResult checked(
            AwsValidationResult.Status status, AwsValidationResult.Reason reason, Instant time) {
        return new AwsValidationResult(
                status,
                reason,
                time,
                time,
                AwsValidationResult.METHOD,
                AwsValidationResult.VERSION);
    }
}
