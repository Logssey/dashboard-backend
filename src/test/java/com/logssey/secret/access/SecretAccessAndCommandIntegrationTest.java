package com.logssey.secret.access;

import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.command.SecretCommandExecutor;
import com.logssey.secret.command.SecretCommandResult;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SecretAccessAndCommandIntegrationTest {
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static JdbcTemplate jdbc;
    private static DataSourceTransactionManager transactions;
    private SecretAccessService access;
    private SecretCommandExecutor commands;
    private SecretPrincipal security;
    private SecretPrincipal remediator;
    private SecretPrincipal operations;
    private long firstConnection;
    private long secondConnection;
    private long firstOccurrence;
    private long secondOccurrence;

    @BeforeAll
    static void startDatabase() {
        POSTGRES.start();
        var dataSource = new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        jdbc = new JdbcTemplate(dataSource);
        transactions = new DataSourceTransactionManager(dataSource);
        Flyway.configure().dataSource(dataSource).target("12").load().migrate();
        // A nonempty shared V12 database upgrades without deleting or inventing application data.
        jdbc.update("""
                INSERT INTO dashboard_users (login_id,password_hash,display_name,role)
                VALUES ('preserved','hash','Preserved','ADMIN')
                """);
        Flyway.configure().dataSource(dataSource).load().migrate();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM dashboard_users WHERE login_id='preserved'",
                Long.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM flyway_schema_history WHERE success AND version IN ('11','12','13')",
                Long.class)).isEqualTo(3);
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @BeforeEach
    void reset() {
        jdbc.execute("TRUNCATE secret_connections, dashboard_users RESTART IDENTITY CASCADE");
        access = new SecretAccessService(jdbc);
        commands = new SecretCommandExecutor(jdbc, transactions);
        user("admin");
        security = user("security");
        remediator = user("remediator");
        operations = user("operations");
        firstConnection = connection("First");
        secondConnection = connection("Second");
        firstOccurrence = occurrence(firstConnection, "11");
        secondOccurrence = occurrence(secondConnection, "22");
    }

    @Test
    void dashboardAdminNeverImpliesSecretAuthorityAndRevocationIsImmediate() {
        var admin = access.requirePrincipal("admin");
        assertCode(ErrorCode.FORBIDDEN, () -> access.requireAnyRole(admin));
        assertCode(ErrorCode.UNAUTHENTICATED, () -> access.requirePrincipal(null));
        assertCode(ErrorCode.UNAUTHENTICATED, () -> access.requirePrincipal("missing"));
        grant(security, SecretRole.SECURITY, firstConnection);
        assertThat(access.canReadOccurrence(security, firstOccurrence)).isTrue();
        assertThat(access.canReadOccurrence(security, secondOccurrence)).isFalse();
        assertCode(ErrorCode.NOT_FOUND, () -> access.requireOccurrenceRead(security, secondOccurrence));
        assertCode(ErrorCode.NOT_FOUND, () -> access.requireOccurrenceRead(security, Long.MAX_VALUE));
        assertCode(ErrorCode.FORBIDDEN, () -> access.requireGlobalRead(security));

        jdbc.update("UPDATE secret_role_grants SET revoked_at=now() WHERE user_id=?", security.userId());
        assertThat(access.canReadOccurrence(security, firstOccurrence)).isFalse();
        assertCode(ErrorCode.FORBIDDEN, () -> access.requireAnyRole(security));
    }

    @Test
    void operationsCanInspectConnectionFactsButNotCredentialLocations() {
        grant(operations, SecretRole.OPERATIONS, firstConnection);
        assertThat(access.canReadConnectionFacts(operations, firstConnection)).isTrue();
        assertThat(access.canReadConnectionFacts(operations, secondConnection)).isFalse();
        assertThat(access.canReadOccurrence(operations, firstOccurrence)).isFalse();
        assertCode(ErrorCode.FORBIDDEN, () -> access.requireGlobalRead(operations));
        assertCode(ErrorCode.NOT_FOUND, () -> access.requireConnectionFactsRead(operations, secondConnection));
        grant(security, SecretRole.SECURITY, null);
        access.requireGlobalRead(security);
        assertThat(access.canReadOccurrence(security, firstOccurrence)).isTrue();
        assertThat(access.canReadOccurrence(security, secondOccurrence)).isTrue();
    }

    @Test
    void remediatorRequiresBothAssignmentAndLiveConnectionRole() {
        grant(remediator, SecretRole.REMEDIATOR, firstConnection);
        assertThat(access.canReadOccurrence(remediator, firstOccurrence)).isFalse();
        long caseId = jdbc.queryForObject("""
                INSERT INTO secret_response_cases (credential_set_id,opening_occurrence_id,
                    opened_by_user_id,opening_reason,case_origin,assigned_user_id)
                SELECT credential_set_id,occurrence_id,?,'ASSESSED_EXPOSURE','TEST',?
                FROM secret_occurrences WHERE occurrence_id=? RETURNING case_id
                """, Long.class, security.userId(), remediator.userId(), firstOccurrence);
        jdbc.update("""
                INSERT INTO secret_case_occurrences(case_id,occurrence_id,credential_set_id)
                SELECT ?,occurrence_id,credential_set_id FROM secret_occurrences WHERE occurrence_id=?
                """, caseId, firstOccurrence);
        assertThat(access.canReadOccurrence(remediator, firstOccurrence)).isTrue();
        assertThat(access.canReadOccurrence(remediator, secondOccurrence)).isFalse();
        jdbc.update("UPDATE secret_response_cases SET assigned_user_id=NULL,assigned_team='Responders' WHERE case_id=?", caseId);
        assertThat(access.canReadOccurrence(remediator, firstOccurrence)).isFalse();
        jdbc.update("INSERT INTO secret_team_memberships(user_id,team_name,added_by_user_id) VALUES (?,'Responders',?)",
                remediator.userId(), security.userId());
        assertThat(access.canReadOccurrence(remediator, firstOccurrence)).isTrue();
        jdbc.update("UPDATE secret_team_memberships SET removed_at=now() WHERE user_id=?", remediator.userId());
        assertThat(access.canReadOccurrence(remediator, firstOccurrence)).isFalse();
    }

    @Test
    void concurrentRetryPersistsExactlyOneMutationResultAndAudit() throws Exception {
        grant(operations, SecretRole.OPERATIONS, firstConnection);
        var calls = new AtomicInteger();
        var start = new CountDownLatch(1);
        var futures = new ArrayList<java.util.concurrent.Future<SecretCommandResult>>();
        try (var pool = Executors.newFixedThreadPool(4)) {
            for (int i = 0; i < 4; i++) futures.add(pool.submit(() -> {
                start.await();
                return commands.execute(operations, SecretCommandExecutor.Kind.MANUAL_SCAN,
                        "public-test-retry", SecretCommandExecutor.digestSafeIds(firstConnection),
                        () -> access.requireConnectionRole(operations, firstConnection, SecretRole.OPERATIONS),
                        () -> {
                            calls.incrementAndGet();
                            jdbc.update("UPDATE secret_connections SET scope_version=scope_version+1 WHERE connection_id=?", firstConnection);
                            return new SecretCommandResult(101, 0, SecretCommandResult.Status.PENDING);
                        });
            }));
            start.countDown();
            for (var future : futures) assertThat(future.get(30, TimeUnit.SECONDS))
                    .isEqualTo(new SecretCommandResult(101, 0, SecretCommandResult.Status.PENDING));
        }
        assertThat(calls).hasValue(1);
        assertThat(jdbc.queryForObject("SELECT scope_version FROM secret_connections WHERE connection_id=?",
                Long.class, firstConnection)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_command_idempotency", Long.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_audit_events", Long.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT idempotency_key FROM secret_command_idempotency", String.class))
                .doesNotContain("public-test-retry");
        assertThat(jdbc.queryForObject("SELECT safe_changes::text FROM secret_audit_events", String.class))
                .isEqualTo("{\"status\": \"PENDING\"}");
    }

    @Test
    void replayRejectsChangedBodyOrRevokedPermissionWithoutNewAudit() {
        grant(operations, SecretRole.OPERATIONS, firstConnection);
        var expected = execute(firstConnection, () -> new SecretCommandResult(101, 0, SecretCommandResult.Status.PENDING));
        assertThat(execute(firstConnection, () -> { throw new AssertionError("Replay must not run"); })).isEqualTo(expected);
        assertCode(ErrorCode.CONFLICT, () -> execute(secondConnection,
                () -> new SecretCommandResult(102, 0, SecretCommandResult.Status.PENDING)));
        jdbc.update("UPDATE secret_role_grants SET revoked_at=now() WHERE user_id=?", operations.userId());
        assertCode(ErrorCode.FORBIDDEN, () -> execute(firstConnection,
                () -> { throw new AssertionError("Revoked replay must not run"); }));
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_audit_events", Long.class)).isEqualTo(1);
    }

    @Test
    void failedCommandAndStaleVersionLeaveNoMutationIdempotencyOrAudit() {
        grant(operations, SecretRole.OPERATIONS, firstConnection);
        assertCode(ErrorCode.CONFLICT, () -> execute(firstConnection, () -> {
            jdbc.update("UPDATE secret_connections SET scope_version=2 WHERE connection_id=?", firstConnection);
            throw new ApiException(ErrorCode.CONFLICT);
        }));
        assertThat(jdbc.queryForObject("SELECT scope_version FROM secret_connections WHERE connection_id=?",
                Long.class, firstConnection)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_command_idempotency", Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM secret_audit_events", Long.class)).isZero();
        assertCode(ErrorCode.CONFLICT, () -> SecretCommandExecutor.requireExpectedVersion(0L, 1));
        assertCode(ErrorCode.INVALID_INPUT, () -> SecretCommandExecutor.requireExpectedVersion(null, 1));
        SecretCommandExecutor.requireExpectedVersion(1L, 1);
    }

    private SecretCommandResult execute(long digestId, java.util.function.Supplier<SecretCommandResult> mutation) {
        return commands.execute(operations, SecretCommandExecutor.Kind.MANUAL_SCAN, "same-key",
                SecretCommandExecutor.digestSafeIds(digestId),
                () -> access.requireConnectionRole(operations, firstConnection, SecretRole.OPERATIONS), mutation);
    }

    private SecretPrincipal user(String login) {
        return new SecretPrincipal(jdbc.queryForObject("""
                INSERT INTO dashboard_users(login_id,password_hash,display_name,role)
                VALUES (?,'hash',?,'ADMIN') RETURNING user_id
                """, Long.class, login, login));
    }

    private void grant(SecretPrincipal principal, SecretRole role, Long connectionId) {
        jdbc.update("""
                INSERT INTO secret_role_grants(user_id,role,connection_id,granted_by_user_id,grant_source)
                VALUES (?,?,?,?,'MANUAL')
                """, principal.userId(), role.name(), connectionId, security.userId());
    }

    private long connection(String name) {
        return jdbc.queryForObject("""
                INSERT INTO secret_connections(provider,display_name,auth_ref,status,scope_version)
                VALUES ('GITHUB',?,'opaque-ref','ACTIVE',1) RETURNING connection_id
                """, Long.class, name);
    }

    private long occurrence(long connectionId, String digest) {
        long scope = jdbc.queryForObject("""
                INSERT INTO secret_connection_scopes(connection_id,scope_key,revision,content_type,approved_ref,enabled)
                VALUES (?,'fixture',1,'GITHUB_REPOSITORY_FILES','github://Example/fixture/main/src/',true)
                RETURNING scope_id
                """, Long.class, connectionId);
        long credential = jdbc.queryForObject("""
                INSERT INTO secret_credential_sets(issuer,credential_type,component_state,fingerprint,
                    fingerprint_key_version,masked_label,first_seen_at,last_seen_at)
                VALUES ('AWS','AWS_ACCESS_KEY_PAIR','CONFIRMED',decode(?,'hex'),'test','AWS masked',now(),now())
                RETURNING credential_set_id
                """, Long.class, digest);
        return jdbc.queryForObject("""
                INSERT INTO secret_occurrences(credential_set_id,connection_id,scope_id,source_object_ref,
                    location_key,environment,exposure_status,exposure_range,presence_status,first_seen_at,last_seen_at)
                VALUES (?,?,?,'fixture/config.txt','L1','UNKNOWN','UNKNOWN','UNKNOWN','PRESENT',now(),now())
                RETURNING occurrence_id
                """, Long.class, credential, connectionId, scope);
    }

    private void assertCode(ErrorCode code, Runnable call) {
        assertThatThrownBy(call::run).isInstanceOfSatisfying(ApiException.class,
                error -> assertThat(error.errorCode()).isEqualTo(code));
    }
}
