package com.logssey.secret.query;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Optional;

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

class SecretInventoryServiceTest {
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static JdbcTemplate jdbc;
    private SecretInventoryService service;

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
        jdbc.update("""
                INSERT INTO dashboard_users (login_id, password_hash, display_name, role)
                VALUES ('admin', 'test-hash', 'Admin', 'ADMIN')
                """);
        service = new SecretInventoryService(new SecretInventoryRepository(jdbc));
    }

    @Test
    void listsOneConfirmedCredentialWithDistinctLocationsAndKeepsPartialCandidatesSeparate() {
        long connection = connection("ACTIVE", "Fixture GitHub");
        long scope = scope(connection, "fixtures/", true);
        long confirmed = credential("CONFIRMED", "a1", "AWS AKIA••••1234");
        long candidateA = credential("CANDIDATE", "b1", "AWS AKIA••••1234");
        long candidateB = credential("CANDIDATE", "b2", "AWS AKIA••••1234");
        occurrence(confirmed, connection, scope, "repo/one.txt", "L4");
        occurrence(confirmed, connection, scope, "repo/two.java", "L22");
        occurrence(candidateA, connection, scope, "repo/only-id-a.txt", "L1");
        occurrence(candidateB, connection, scope, "repo/only-id-b.txt", "L1");

        var all = service.list(0, 20, "ALL", "ALL", "admin");
        assertThat(all.total()).isEqualTo(3);
        assertThat(all.items()).hasSize(3);
        assertThat(all.items()).extracting(SecretSummaryResponse::componentState)
                .containsExactlyInAnyOrder("CONFIRMED", "CANDIDATE", "CANDIDATE");
        assertThat(service.list(0, 20, "AWS", "CONFIRMED", "admin").items())
                .singleElement()
                .satisfies(item -> {
                    assertThat(item.id()).isEqualTo(confirmed);
                    assertThat(item.occurrenceCount()).isEqualTo(2);
                    assertThat(item.severity()).isEqualTo("UNASSESSED");
                    assertThat(item.validationStatus()).isEqualTo("UNCHECKED");
                    assertThat(item.maskedLabel()).isEqualTo("AWS AKIA••••1234");
                });
        var detail = service.detail(confirmed, "admin");
        assertThat(detail.occurrences()).hasSize(2);
        assertThat(detail.occurrences()).extracting(SecretOccurrenceResponse::sourceObjectRef)
                .containsExactly("repo/one.txt", "repo/two.java");
        assertThat(detail.occurrences()).extracting(SecretOccurrenceResponse::environment)
                .containsOnly("UNKNOWN");
        assertThat(detail.occurrences()).extracting(SecretOccurrenceResponse::locationKey)
                .containsExactly("L4", "L22");
        assertThat(service.detail(candidateA, "admin").occurrences()).hasSize(1);
        assertThat(service.detail(candidateB, "admin").occurrences()).hasSize(1);
        assertThat(detail.toString()).doesNotContain("a1", "b1", "b2");
    }

    @Test
    void paginatesAndValidatesFiltersWithoutReadingLegacyCredentials() {
        credential("CONFIRMED", "aa", "AWS AKIA••••0001");
        credential("CONFIRMED", "bb", "AWS AKIA••••0002");
        assertThat(service.list(0, 1, "ALL", "ALL", "admin").total()).isEqualTo(2);
        assertThat(service.list(0, 1, "ALL", "ALL", "admin").items()).hasSize(1);
        assertThat(service.list(1, 1, "ALL", "ALL", "admin").items()).hasSize(1);
        assertThat(service.list(2, 1, "ALL", "ALL", "admin").items()).isEmpty();
        assertCode(ErrorCode.INVALID_INPUT, () -> service.list(-1, 20, "ALL", "ALL", "admin"));
        assertCode(ErrorCode.INVALID_INPUT, () -> service.list(0, 101, "ALL", "ALL", "admin"));
        assertCode(ErrorCode.INVALID_INPUT, () -> service.list(0, 20, "AWS' OR TRUE --", "ALL", "admin"));
        assertCode(ErrorCode.NOT_FOUND, () -> service.detail(999, "admin"));
    }

    @Test
    void reportsOnlyLatestValidationAttemptAndAllowlistedReason() {
        long connection = connection("ACTIVE", "Fixture GitHub");
        long scope = scope(connection, "fixtures/", true);
        long credential = credential("CONFIRMED", "cc", "AWS AKIA••••0003");
        occurrence(credential, connection, scope, "repo/key.txt", "L3");
        long[] run = run(connection);
        OffsetDateTime base = OffsetDateTime.now(ZoneOffset.UTC).truncatedTo(ChronoUnit.MICROS)
                .minusMinutes(5);
        validation(credential, run, "VALID", "AUTHENTICATED", base,
                base.plusSeconds(2), base.plusSeconds(1));
        validation(credential, run, "UNKNOWN", "RATE_LIMITED", base.plusMinutes(1),
                base.plusMinutes(1).plusSeconds(2), base.plusMinutes(1).plusSeconds(1));

        var latest = service.detail(credential, "admin");
        assertThat(latest.validationStatus()).isEqualTo("UNKNOWN");
        assertThat(latest.validationReasonCode()).isEqualTo("RATE_LIMITED");
        assertThat(latest.validatedAt()).isEqualTo(base.plusMinutes(1).plusSeconds(2));
        assertThat(latest.validationCheckedAt()).isEqualTo(base.plusMinutes(1).plusSeconds(1));
        assertThat(service.list(0, 20, "AWS", "CONFIRMED", "admin").items())
                .singleElement()
                .satisfies(item -> {
                    assertThat(item.validationStatus()).isEqualTo("UNKNOWN");
                    assertThat(item.validationReasonCode()).isEqualTo("RATE_LIMITED");
                });

        validation(credential, run, "UNCHECKED", "SHOULD_NOT_DISCLOSE",
                base.plusMinutes(2), base.plusMinutes(2).plusSeconds(1), null);
        var unrecognized = service.detail(credential, "admin");
        assertThat(unrecognized.validationStatus()).isEqualTo("UNCHECKED");
        assertThat(unrecognized.validationReasonCode()).isEqualTo("UNSPECIFIED_REASON");
        assertThat(unrecognized.validationCheckedAt()).isNull();
        assertThat(service.list(0, 20, "ALL", "ALL", "admin").items().getFirst().validationReasonCode())
                .isEqualTo("UNSPECIFIED_REASON");

        validation(credential, run, "UNCHECKED", "SYNTHETIC_FIXTURE",
                base.plusMinutes(3), base.plusMinutes(3).plusSeconds(1), null);
        assertThat(service.detail(credential, "admin").validationReasonCode())
                .isEqualTo("SYNTHETIC_FIXTURE");
    }

    @Test
    void onlyDatabaseAdminsMayReadInventoryAndActiveConnectionsWithApprovedScopes() {
        long active = connection("ACTIVE", "Approved");
        scope(active, "fixtures/", true);
        scope(active, "draft/", false);
        long empty = connection("ACTIVE", "No approved scope");
        scope(empty, "draft/", false);
        long paused = connection("PAUSED", "Paused");
        scope(paused, "fixtures/", true);
        long unsupported = connection("AWS", "ACTIVE", "AWS not yet executable");
        scope(unsupported, "fixtures/", true);

        var result = service.connections("admin");
        assertThat(result.items()).singleElement().satisfies(item -> {
            assertThat(item.connectionId()).isEqualTo(active);
            assertThat(item.provider()).isEqualTo("GITHUB");
            assertThat(item.status()).isEqualTo("ACTIVE");
            assertThat(item.approvedScopeCount()).isEqualTo(1);
        });
        assertThat(result.toString()).doesNotContain("auth-ref", "approved-ref");
        assertCode(ErrorCode.UNAUTHENTICATED,
                () -> service.list(0, 20, "ALL", "ALL", null));
        assertCode(ErrorCode.UNAUTHENTICATED, () -> service.connections("missing"));
        var nonAdmin = new SecretInventoryService(new SecretInventoryRepository(jdbc) {
            @Override
            Optional<String> actorRole(String loginId) {
                return Optional.of("VIEWER");
            }
        });
        assertCode(ErrorCode.FORBIDDEN, () -> nonAdmin.list(0, 20, "ALL", "ALL", "viewer"));
        assertCode(ErrorCode.FORBIDDEN, () -> nonAdmin.detail(1, "viewer"));
        assertCode(ErrorCode.FORBIDDEN, () -> nonAdmin.connections("viewer"));
    }

    private long connection(String status, String name) {
        return connection("GITHUB", status, name);
    }

    private long connection(String provider, String status, String name) {
        return jdbc.queryForObject("""
                INSERT INTO secret_connections
                    (provider, display_name, auth_ref, status, scope_version)
                VALUES (?, ?, 'auth-ref-test-only', ?, 1) RETURNING connection_id
                """, Long.class, provider, name, status);
    }

    private long scope(long connection, String key, boolean enabled) {
        return jdbc.queryForObject("""
                INSERT INTO secret_connection_scopes
                    (connection_id, scope_key, revision, content_type, approved_ref, enabled)
                VALUES (?, ?, 1, 'TEXT', 'approved-ref-test-only', ?)
                RETURNING scope_id
                """, Long.class, connection, key, enabled);
    }

    private long credential(String state, String digest, String label) {
        return jdbc.queryForObject("""
                INSERT INTO secret_credential_sets
                    (issuer, credential_type, component_state, fingerprint, candidate_locator,
                     fingerprint_key_version, masked_label, first_seen_at, last_seen_at)
                VALUES ('AWS', 'AWS_ACCESS_KEY_PAIR', ?,
                        CASE WHEN ? = 'CONFIRMED' THEN decode(?, 'hex') END,
                        CASE WHEN ? = 'CANDIDATE' THEN decode(?, 'hex') END,
                        'test-v1', ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                RETURNING credential_set_id
                """, Long.class, state, state, digest, state, digest, label);
    }

    private void occurrence(long credential, long connection, long scope, String source, String location) {
        jdbc.update("""
                INSERT INTO secret_occurrences
                    (credential_set_id, connection_id, scope_id, source_object_ref, location_key,
                     environment, exposure_status, exposure_range, presence_status,
                     first_seen_at, last_seen_at)
                VALUES (?, ?, ?, ?, ?, 'UNKNOWN', 'UNKNOWN', 'UNKNOWN', 'PRESENT',
                        CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """, credential, connection, scope, source, location);
    }

    private long[] run(long connection) {
        OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC).minusMinutes(10);
        long job = jdbc.queryForObject("""
                INSERT INTO secret_jobs
                    (kind, connection_id, scheduled_at, available_at,
                     attempt_no, max_attempts, status)
                VALUES ('FULL_SCAN', ?, ?, ?, 0, 3, 'PENDING')
                RETURNING job_id
                """, Long.class, connection, now, now);
        long run = jdbc.queryForObject("""
                INSERT INTO secret_scan_runs
                    (job_id, connection_id, trigger_type, scope_version,
                     scheduled_at, requested_at, collection_status,
                     detection_status, validation_status, result_status)
                VALUES (?, ?, 'MANUAL', 1, ?, ?, 'PENDING', 'PENDING', 'PENDING', 'PENDING')
                RETURNING run_id
                """, Long.class, job, connection, now, now);
        return new long[]{job, run};
    }

    private void validation(long credential, long[] run, String result, String reason,
                            OffsetDateTime requested, OffsetDateTime completed,
                            OffsetDateTime checked) {
        jdbc.update("""
                INSERT INTO secret_validation_attempts
                    (credential_set_id, job_id, run_id, validator_id, validator_version,
                     endpoint_class, requested_at, completed_at, provider_checked_at,
                     result, reason_code)
                VALUES (?, ?, ?, 'AWS_STS_GET_CALLER_IDENTITY', '1', 'AWS_STS',
                        ?, ?, ?, ?, ?)
                """, credential, run[0], run[1], requested, completed, checked, result, reason);
    }

    private void assertCode(ErrorCode expected, Runnable call) {
        assertThatThrownBy(call::run).isInstanceOf(ApiException.class)
                .satisfies(error -> assertThat(((ApiException) error).errorCode()).isEqualTo(expected));
    }
}
