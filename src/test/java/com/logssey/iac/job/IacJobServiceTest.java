package com.logssey.iac.job;

import java.time.OffsetDateTime;
import java.util.Map;

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

class IacJobServiceTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final OffsetDateTime START = OffsetDateTime.parse("2026-10-19T03:00:00+09:00");
    private static JdbcTemplate jdbc;
    private static DataSourceTransactionManager transactions;
    private IacJobService service;

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
        jdbc.execute("TRUNCATE iac_jobs, iac_audit_events, dashboard_users RESTART IDENTITY CASCADE");
        jdbc.update("""
                INSERT INTO dashboard_users (login_id, password_hash, display_name, role)
                VALUES ('admin', 'test-hash', 'Test Admin', 'ADMIN')
                """);
        service = new IacJobService(new IacJobRepository(jdbc), transactions);
    }

    @Test
    void successfulCollectionRecordsTheRunAndQueuesOneEnrichment() {
        var first = service.recordCollectGraph(request("SUCCEEDED"), "admin");
        var second = service.recordCollectGraph(request("SUCCEEDED"), "admin");

        assertThat(first.enrichJobId()).isNotNull().isEqualTo(second.enrichJobId());
        assertThat(first.stateJobId()).isNotNull().isEqualTo(second.stateJobId());
        assertThat(jdbc.queryForObject("""
                SELECT status || '/' || (stats ->> 'nodes') || '/' || (finished_at - available_at)
                FROM iac_jobs WHERE job_id = ?
                """, String.class, first.jobId())).isEqualTo("SUCCEEDED/120/00:20:00");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_jobs WHERE kind = 'ENRICH_GRAPH'", Long.class))
                .isEqualTo(1L);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_jobs WHERE kind = 'CHECK_STATE'", Long.class))
                .isEqualTo(1L);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_audit_events", Long.class)).isEqualTo(2L);
    }

    @Test
    void failedCollectionQueuesNothing() {
        var failed = service.recordCollectGraph(request("FAILED"), "admin");
        assertThat(failed.enrichJobId()).isNull();
        assertThat(failed.stateJobId()).isNull();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_jobs WHERE kind = 'ENRICH_GRAPH'", Long.class))
                .isZero();
    }

    @Test
    void rejectsBackwardsTimesAndNonAdmins() {
        assertThatThrownBy(() -> service.recordCollectGraph(new CollectGraphRunRequest("SUCCEEDED", START,
                START.minusMinutes(1), Map.of()), "admin"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.INVALID_INPUT));
        assertThatThrownBy(() -> service.recordCollectGraph(request("SUCCEEDED"), "someone"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.FORBIDDEN));
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_jobs", Long.class)).isZero();
    }

    private static CollectGraphRunRequest request(String status) {
        return new CollectGraphRunRequest(status, START, START.plusMinutes(20), Map.of("nodes", 120L));
    }
}
