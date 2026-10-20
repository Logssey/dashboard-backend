package com.logssey.iac.finding;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

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

class IacFindingServiceTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static JdbcTemplate jdbc;
    private static DataSourceTransactionManager transactions;
    private IacFindingService service;
    private long finding;

    @BeforeAll
    static void startDatabase() {
        POSTGRES.start();
        var datasource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(datasource).load().migrate();
        jdbc = new JdbcTemplate(datasource);
        transactions = new DataSourceTransactionManager(datasource);
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @BeforeEach
    void reset() {
        jdbc.execute("TRUNCATE iac_findings, iac_jobs, iac_audit_events, dashboard_users RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO dashboard_users (login_id, password_hash, display_name, role) VALUES "
                + "('admin', 'h', 'Admin', 'ADMIN'), ('teammate', 'h', 'Teammate', 'ADMIN')");
        long job = jdbc.queryForObject("INSERT INTO iac_jobs (kind, trigger_type, status) VALUES ('CHECK_DRIFT', 'SCHEDULED', 'SUCCEEDED') "
                + "RETURNING job_id", Long.class);
        finding = jdbc.queryForObject("""
                INSERT INTO iac_findings (rule_id, source, enforcement, severity, environment, resource_address, fingerprint,
                                          last_job_id, first_seen_at, last_seen_at)
                VALUES ('drift.high', 'DRIFT', 'WARN', 'HIGH', 'PROD', 'dns', 'fp', ?, now(), now()) RETURNING finding_id
                """, Long.class, job);
        service = new IacFindingService(new IacFindingRepository(jdbc), transactions);
    }

    @Test
    void assignsAcceptsAndAuditsWithOptimisticLocking() {
        var assigned = service.update(finding, new FindingUpdateRequest(2L, null, null, 0L), "admin");
        assertThat(assigned.assigneeUserId()).isEqualTo(2L);
        assertThat(assigned.status()).isEqualTo("OPEN");
        assertThat(assigned.version()).isEqualTo(1);

        assertThatThrownBy(() -> service.update(finding, new FindingUpdateRequest(null, null, "ACCEPTED", 0L), "admin"))
                .as("오래된 version").satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.CONFLICT));

        var accepted = service.update(finding, new FindingUpdateRequest(null, true, "ACCEPTED", 1L), "admin");
        assertThat(accepted.status()).isEqualTo("ACCEPTED");
        assertThat(accepted.assigneeUserId()).isNull();
        assertThat(jdbc.queryForList("SELECT (before_safe ->> 'status') || '>' || (after_safe ->> 'status') FROM iac_audit_events "
                + "WHERE entity_id = ? ORDER BY audit_id", String.class, finding)).containsExactly("OPEN>OPEN", "OPEN>ACCEPTED");
    }

    @Test
    void rejectsUnknownUsersAndFindings() {
        assertThatThrownBy(() -> service.update(finding, new FindingUpdateRequest(99L, null, null, 0L), "admin"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.INVALID_INPUT));
        assertThatThrownBy(() -> service.update(finding, new FindingUpdateRequest(2L, true, null, 0L), "admin"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.INVALID_INPUT));
        assertThatThrownBy(() -> service.update(999, new FindingUpdateRequest(null, null, "ACCEPTED", 0L), "admin"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.NOT_FOUND));
        assertThatThrownBy(() -> service.update(finding, new FindingUpdateRequest(null, null, "ACCEPTED", 0L), "nobody"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.FORBIDDEN));
    }
}
