package com.logssey.secret.response;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecretManualTriageTest {
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static JdbcTemplate jdbc;
    private SecretTriageService triage;
    private SecretCaseService cases;
    private long actorId;

    @BeforeAll
    static void startDatabase() {
        POSTGRES.start();
        var datasource = new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(datasource).load().migrate();
        jdbc = new JdbcTemplate(datasource);
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @BeforeEach
    void reset() {
        jdbc.execute("TRUNCATE secret_connections, dashboard_users RESTART IDENTITY CASCADE");
        actorId = jdbc.queryForObject("""
                INSERT INTO dashboard_users (login_id, password_hash, display_name, role)
                VALUES ('security', 'test-hash', 'Security', 'ADMIN') RETURNING user_id
                """, Long.class);
        var casesRepository = new SecretCaseRepository(jdbc);
        triage = new SecretTriageService(new SecretTriageRepository(jdbc), casesRepository);
        cases = new SecretCaseService(casesRepository);
    }

    @Test
    void syntheticScopeRequiresExplicitTestClassificationAndAuditedAssessment() {
        var fixture = fixture("github://Logssey/test-find-key/main/fixtures/", "CONFIRMED");
        assertThat(triage.scope(fixture.scopeId(), "security").responseOrigin())
                .isEqualTo("UNCLASSIFIED");
        assertThat(triage.scope(fixture.scopeId(), "security").allowedOrigins())
                .containsExactly("TEST");
        assertThat(triage.occurrence(fixture.occurrenceId(), "security").exposureStatus())
                .isEqualTo("UNKNOWN");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_response_cases", Long.class))
                .isZero();
        assertCode(ErrorCode.CONFLICT, () -> cases.open(fixture.secretId(),
                openRequest(fixture, 1, 1), "security"));
        assertCode(ErrorCode.CONFLICT, () -> triage.classify(fixture.scopeId(),
                new SecretScopeOriginRequest("PRODUCTION", "APPROVED_PRODUCTION_SOURCE", 0L),
                "security"));
        var classified = triage.classify(fixture.scopeId(),
                new SecretScopeOriginRequest("TEST", "APPROVED_TEST_FIXTURE", 0L), "security");
        assertThat(classified.responseOrigin()).isEqualTo("TEST");
        assertThat(classified.responseOriginVersion()).isEqualTo(1);
        assertThat(classified.allowedOrigins()).isEmpty();
        assertThat(classified.history()).singleElement().satisfies(item -> {
            assertThat(item.reasonCode()).isEqualTo("APPROVED_TEST_FIXTURE");
            assertThat(item.actorUserId()).isEqualTo(actorId);
        });
        assertCode(ErrorCode.CONFLICT, () -> triage.classify(fixture.scopeId(),
                new SecretScopeOriginRequest("PRODUCTION", "APPROVED_PRODUCTION_SOURCE", 1L),
                "security"));
        assertCode(ErrorCode.INVALID_INPUT, () -> triage.assess(fixture.occurrenceId(),
                new SecretExposureAssessmentRequest("ABNORMAL", "SIMULATED_EXPOSURE",
                        fixture.otherFindingId(), 0L), "security"));
        var assessed = triage.assess(fixture.occurrenceId(),
                new SecretExposureAssessmentRequest("ABNORMAL", "SIMULATED_EXPOSURE",
                        fixture.findingId(), 0L), "security");
        assertThat(assessed.exposureStatus()).isEqualTo("ABNORMAL");
        assertThat(assessed.assessmentVersion()).isEqualTo(1);
        assertThat(assessed.history()).singleElement().satisfies(item -> {
            assertThat(item.findingId()).isEqualTo(fixture.findingId());
            assertThat(item.findingRuleId()).isEqualTo("test-rule");
            assertThat(item.fromStatus()).isEqualTo("UNKNOWN");
            assertThat(item.actorUserId()).isEqualTo(actorId);
        });
        assertCode(ErrorCode.CONFLICT, () -> cases.open(fixture.secretId(),
                openRequest(fixture, 2, 1), "security"));
        assertCode(ErrorCode.CONFLICT, () -> cases.open(fixture.secretId(),
                openRequest(fixture, 1, 2), "security"));
        var opened = cases.open(fixture.secretId(), openRequest(fixture, 1, 1), "security");
        assertThat(opened.caseOrigin()).isEqualTo("TEST");
        assertThat(cases.list(0, 20, "PRODUCTION", "security").total()).isZero();
        assertThat(cases.list(0, 20, "TEST", "security").total()).isEqualTo(1);
        assertCode(ErrorCode.CONFLICT, () -> triage.assess(fixture.occurrenceId(),
                new SecretExposureAssessmentRequest("NORMAL", "AUTHORIZED_LOCATION",
                        fixture.findingId(), 1L), "security"));
    }

    @Test
    void productionRequiresDifferentReasonAndLatestImmutableAssessment() {
        var fixture = fixture("github://Logssey/production-repo/main/src/", "CONFIRMED");
        assertThat(triage.scope(fixture.scopeId(), "security").allowedOrigins())
                .containsExactly("TEST", "PRODUCTION");
        triage.classify(fixture.scopeId(), new SecretScopeOriginRequest(
                "PRODUCTION", "APPROVED_PRODUCTION_SOURCE", 0L), "security");
        assertCode(ErrorCode.INVALID_INPUT, () -> triage.assess(fixture.occurrenceId(),
                new SecretExposureAssessmentRequest("ABNORMAL", "SIMULATED_EXPOSURE",
                        fixture.findingId(), 0L), "security"));
        triage.assess(fixture.occurrenceId(), new SecretExposureAssessmentRequest(
                "NORMAL", "AUTHORIZED_LOCATION", fixture.findingId(), 0L), "security");
        assertCode(ErrorCode.CONFLICT, () -> cases.open(fixture.secretId(),
                openRequest(fixture, 1, 1), "security"));
        assertCode(ErrorCode.CONFLICT, () -> triage.assess(fixture.occurrenceId(),
                new SecretExposureAssessmentRequest("ABNORMAL", "UNAPPROVED_SOURCE_LOCATION",
                        fixture.findingId(), 0L), "security"));
        triage.assess(fixture.occurrenceId(), new SecretExposureAssessmentRequest(
                "ABNORMAL", "UNAPPROVED_SOURCE_LOCATION", fixture.findingId(), 1L), "security");
        assertCode(ErrorCode.CONFLICT, () -> cases.open(fixture.secretId(),
                openRequest(fixture, 1, 1), "security"));
        assertThat(cases.open(fixture.secretId(), openRequest(fixture, 2, 1), "security")
                .caseOrigin()).isEqualTo("PRODUCTION");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM secret_exposure_assessments", Long.class))
                .isEqualTo(2);
    }

    @Test
    void incompleteMissingAndMutableStatusWithoutHistoryCannotOpen() {
        for (String component : new String[] {"CANDIDATE", "METADATA_ONLY"}) {
            var fixture = fixture("github://Logssey/" + component + "/main/src/", component);
            triage.classify(fixture.scopeId(), new SecretScopeOriginRequest(
                    "TEST", "APPROVED_TEST_FIXTURE", 0L), "security");
            assertCode(ErrorCode.CONFLICT, () -> triage.assess(fixture.occurrenceId(),
                    new SecretExposureAssessmentRequest("ABNORMAL", "SIMULATED_EXPOSURE",
                            fixture.findingId(), 0L), "security"));
            assertCode(ErrorCode.CONFLICT, () -> cases.open(fixture.secretId(),
                    openRequest(fixture, 1, 1), "security"));
        }
        var fixture = fixture("github://Logssey/another/main/src/", "CONFIRMED");
        triage.classify(fixture.scopeId(), new SecretScopeOriginRequest(
                "TEST", "APPROVED_TEST_FIXTURE", 0L), "security");
        jdbc.update("UPDATE secret_occurrences SET exposure_status = 'ABNORMAL', "
                + "exposure_assessment_version = 1 WHERE occurrence_id = ?", fixture.occurrenceId());
        assertCode(ErrorCode.CONFLICT, () -> cases.open(fixture.secretId(),
                openRequest(fixture, 1, 1), "security"));
        jdbc.update("UPDATE secret_occurrences SET exposure_status = 'UNKNOWN', "
                + "exposure_assessment_version = 0 WHERE occurrence_id = ?", fixture.occurrenceId());
        triage.assess(fixture.occurrenceId(), new SecretExposureAssessmentRequest(
                "ABNORMAL", "SIMULATED_EXPOSURE", fixture.findingId(), 0L), "security");
        jdbc.update("UPDATE secret_occurrences SET presence_status = 'MISSING' WHERE occurrence_id = ?",
                fixture.occurrenceId());
        assertCode(ErrorCode.CONFLICT, () -> cases.open(fixture.secretId(),
                openRequest(fixture, 1, 1), "security"));
    }

    @Test
    void secretRoleIsDistinctFromDashboardAdminAndScopedToConnection() {
        var fixture = fixture("github://Logssey/test-find-key/main/fixtures/", "CONFIRMED");
        long otherUser = jdbc.queryForObject("""
                INSERT INTO dashboard_users (login_id, password_hash, display_name, role)
                VALUES ('other-admin', 'test-hash', 'Other', 'ADMIN') RETURNING user_id
                """, Long.class);
        assertCode(ErrorCode.FORBIDDEN, () -> triage.scope(fixture.scopeId(), "other-admin"));
        assertCode(ErrorCode.FORBIDDEN, () -> triage.classify(fixture.scopeId(),
                new SecretScopeOriginRequest("TEST", "APPROVED_TEST_FIXTURE", 0L), "other-admin"));
        assertCode(ErrorCode.FORBIDDEN, () -> triage.occurrence(fixture.occurrenceId(), "other-admin"));
        assertCode(ErrorCode.FORBIDDEN, () -> triage.candidates(0, 20, "other-admin"));
        assertCode(ErrorCode.FORBIDDEN, () -> triage.candidate(fixture.secretId(), "other-admin"));
        jdbc.update("""
                INSERT INTO secret_role_grants
                    (user_id, role, connection_id, granted_by_user_id, grant_source)
                VALUES (?, 'SECURITY', ?, ?, 'MANUAL')
                """, otherUser, fixture.connectionId(), actorId);
        assertThat(triage.scope(fixture.scopeId(), "other-admin").scopeId())
                .isEqualTo(fixture.scopeId());
        long deniedConnection = jdbc.queryForObject("""
                INSERT INTO secret_connections
                    (provider, display_name, auth_ref, status, scope_version)
                VALUES ('GITHUB', 'Denied', 'test-ref', 'ACTIVE', 1) RETURNING connection_id
                """, Long.class);
        long deniedScope = jdbc.queryForObject("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref,
                     history_limit, enabled)
                VALUES (?, 'denied', 1, 'GITHUB_REPOSITORY_FILES',
                        'github://private/repo/main/src/', 'CURRENT_COMMIT_ONLY', TRUE)
                RETURNING scope_id
                """, Long.class, deniedConnection);
        long deniedOccurrence = occurrence(fixture.secretId(), deniedConnection, deniedScope,
                "private/should-not-appear.txt");
        assertThat(triage.candidates(0, 20, "other-admin").items()).singleElement()
                .satisfies(item -> assertThat(item.occurrenceCount()).isEqualTo(2));
        assertThat(triage.candidate(fixture.secretId(), "other-admin").occurrences())
                .hasSize(2).noneMatch(item -> item.id() == deniedOccurrence);
        assertCode(ErrorCode.FORBIDDEN,
                () -> triage.occurrence(deniedOccurrence, "other-admin"));
    }

    @Test
    void directTriageReadsRejectPausedOrUnapprovedSources() {
        var fixture = fixture("github://Logssey/production-repo/main/src/", "CONFIRMED");
        assertThat(triage.candidates(0, 20, "security").total()).isEqualTo(1);
        jdbc.update("UPDATE secret_connections SET status = 'PAUSED' WHERE connection_id = ?",
                fixture.connectionId());
        assertThat(triage.candidates(0, 20, "security").total()).isZero();
        assertCode(ErrorCode.NOT_FOUND, () -> triage.scope(fixture.scopeId(), "security"));
        assertCode(ErrorCode.NOT_FOUND,
                () -> triage.occurrence(fixture.occurrenceId(), "security"));
        jdbc.update("UPDATE secret_connections SET status = 'ACTIVE' WHERE connection_id = ?",
                fixture.connectionId());
        jdbc.update("UPDATE secret_connection_scopes SET enabled = FALSE WHERE scope_id = ?",
                fixture.scopeId());
        assertThat(triage.candidates(0, 20, "security").total()).isZero();
        assertCode(ErrorCode.NOT_FOUND, () -> triage.scope(fixture.scopeId(), "security"));
        assertCode(ErrorCode.NOT_FOUND,
                () -> triage.occurrence(fixture.occurrenceId(), "security"));
    }

    @Test
    void fixtureExceptionMatchesOnlyTheExactOwnerAndRepository() {
        assertThat(SecretGithubScopePolicy.syntheticFixture(
                "github://Logssey/test-find-key/main/fixtures/")).isTrue();
        assertThat(SecretGithubScopePolicy.syntheticFixture(
                "github://Other/test-find-key/main/fixtures/")).isFalse();
        assertThat(SecretGithubScopePolicy.syntheticFixture(
                "github://Logssey/test-find-key-copy/main/fixtures/")).isFalse();
    }

    private Fixture fixture(String approvedRef, String component) {
        long connection = jdbc.queryForObject("""
                INSERT INTO secret_connections
                    (provider, display_name, auth_ref, status, scope_version)
                VALUES ('GITHUB', 'Test', 'test-ref', 'ACTIVE', 1) RETURNING connection_id
                """, Long.class);
        long scope = jdbc.queryForObject("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref,
                     history_limit, enabled)
                VALUES (?, ?, 1, 'GITHUB_REPOSITORY_FILES', ?, 'CURRENT_COMMIT_ONLY', TRUE)
                RETURNING scope_id
                """, Long.class, connection, approvedRef, approvedRef);
        jdbc.update("""
                INSERT INTO secret_role_grants
                    (user_id, role, connection_id, granted_by_user_id, grant_source)
                VALUES (?, 'SECURITY', ?, ?, 'MANUAL')
                """, actorId, connection, actorId);
        long secret = jdbc.queryForObject("""
                INSERT INTO secret_credential_sets
                    (issuer, credential_type, component_state, fingerprint, candidate_locator,
                     fingerprint_key_version, masked_label, first_seen_at, last_seen_at)
                VALUES ('GITHUB', 'GITHUB_CLASSIC_PAT', ?,
                        CASE WHEN ? = 'CONFIRMED' THEN decode(md5(random()::text), 'hex') END,
                        CASE WHEN ? = 'CANDIDATE' THEN decode(md5(random()::text), 'hex') END,
                        CASE WHEN ? = 'METADATA_ONLY' THEN NULL ELSE 'test' END,
                        'GITHUB ***', now(), now()) RETURNING credential_set_id
                """, Long.class, component, component, component, component);
        long first = occurrence(secret, connection, scope, "repo/first.txt");
        long second = occurrence(secret, connection, scope, "repo/second.txt");
        long job = jdbc.queryForObject("""
                INSERT INTO secret_jobs
                    (kind, connection_id, scheduled_at, available_at,
                     attempt_no, max_attempts, status)
                VALUES ('FULL_SCAN', ?, now(), now(), 0, 3, 'PENDING') RETURNING job_id
                """, Long.class, connection);
        long run = jdbc.queryForObject("""
                INSERT INTO secret_scan_runs
                    (job_id, connection_id, trigger_type, scope_version, scheduled_at,
                     requested_at, collection_status, detection_status, validation_status, result_status)
                VALUES (?, ?, 'MANUAL', 1, now(), now(), 'SUCCEEDED', 'SUCCEEDED',
                        'PENDING', 'SUCCEEDED') RETURNING run_id
                """, Long.class, job, connection);
        long runScope = jdbc.queryForObject("""
                INSERT INTO secret_run_scopes (run_id, scope_id, collection_status)
                VALUES (?, ?, 'SUCCEEDED') RETURNING run_scope_id
                """, Long.class, run, scope);
        long toolRun = jdbc.queryForObject("""
                INSERT INTO secret_tool_runs
                    (run_scope_id, engine, engine_version, config_hash, status,
                     finding_count, started_at, finished_at)
                VALUES (?, 'GITLEAKS', 'test', 'test', 'SUCCEEDED', 2, now(), now())
                RETURNING tool_run_id
                """, Long.class, runScope);
        long finding = finding(first, run, toolRun, "first");
        long otherFinding = finding(second, run, toolRun, "second");
        return new Fixture(connection, scope, secret, first, finding, otherFinding);
    }

    private long occurrence(long secret, long connection, long scope, String source) {
        return jdbc.queryForObject("""
                INSERT INTO secret_occurrences
                    (credential_set_id, connection_id, scope_id, source_object_ref, location_key,
                     environment, exposure_status, exposure_range, presence_status, first_seen_at, last_seen_at)
                VALUES (?, ?, ?, ?, 'L1', 'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'PRESENT', now(), now())
                RETURNING occurrence_id
                """, Long.class, secret, connection, scope, source);
    }

    private long finding(long occurrence, long run, long toolRun, String key) {
        return jdbc.queryForObject("""
                INSERT INTO secret_findings
                    (occurrence_id, run_id, tool_run_id, finding_key, rule_id,
                     rule_version, masked_context, detected_at)
                VALUES (?, ?, ?, ?, 'test-rule', 'v1', NULL, now()) RETURNING finding_id
                """, Long.class, occurrence, run, toolRun, key);
    }

    private static SecretCaseOpenRequest openRequest(Fixture fixture, long assessmentVersion,
                                                     long originVersion) {
        return new SecretCaseOpenRequest(fixture.occurrenceId(), "ASSESSED_EXPOSURE",
                assessmentVersion, originVersion);
    }

    private static void assertCode(ErrorCode expected, Runnable action) {
        assertThatThrownBy(action::run).isInstanceOf(ApiException.class)
                .satisfies(error -> assertThat(((ApiException) error).errorCode()).isEqualTo(expected));
    }

    record Fixture(long connectionId, long scopeId, long secretId, long occurrenceId,
                   long findingId, long otherFindingId) {
    }
}
