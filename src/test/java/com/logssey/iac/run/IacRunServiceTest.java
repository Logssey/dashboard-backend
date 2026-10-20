package com.logssey.iac.run;

import java.util.List;

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

import static com.logssey.iac.run.IacPlanFixtures.gzipResource;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IacRunServiceTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final String REPO = "Logssey/infrastructure";
    private static final String SHA_1 = "1".repeat(40);
    private static final String SHA_2 = "2".repeat(40);
    private static final String EXEC = "[gate.exec_data_source] plan 중 실행되는 data 소스: data.external.x";
    private static final String UNPINNED = "[gate.module_unpinned] git 모듈 ref 미고정: module.y";
    private static JdbcTemplate jdbc;
    private static DataSourceTransactionManager transactions;
    private IacRunService service;

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
        jdbc.execute("TRUNCATE iac_findings, iac_jobs, iac_runs, iac_repos, iac_audit_events, dashboard_users "
                + "RESTART IDENTITY CASCADE");
        jdbc.update("""
                INSERT INTO dashboard_users (login_id, password_hash, display_name, role)
                VALUES ('admin', 'test-hash', 'Test Admin', 'ADMIN')
                """);
        jdbc.update("INSERT INTO iac_repos (full_name, default_branch, environment) VALUES (?, 'main', 'PROD')", REPO);
        service = new IacRunService(new IacRunRepository(jdbc), new IacPlanInspector(), transactions);
    }

    @Test
    void blockedGateEndsTheRunWithTheHighestSeverity() {
        var created = service.register(request(1, SHA_1, "BLOCKED", EXEC, UNPINNED), "admin");

        assertThat(created.status()).isEqualTo("GATE_FAILED");
        assertThat(jdbc.queryForObject("SELECT verdict || '/' || highest_severity || '/' || (finished_at IS NOT NULL) "
                + "FROM iac_runs WHERE run_id = ?", String.class, created.runId())).isEqualTo("BLOCK/CRITICAL/true");
        assertThat(jdbc.queryForList("SELECT rule_id || '|' || enforcement || '|' || resource_address FROM iac_findings "
                + "ORDER BY rule_id", String.class)).containsExactly(
                "gate.exec_data_source|BLOCK|data.external.x", "gate.module_unpinned|WARN|module.y");
        assertThat(count("iac_jobs")).isZero();
        assertThat(count("iac_audit_events")).isEqualTo(1);
    }

    @Test
    void passedGateWaitsForThePlan() {
        var created = service.register(request(1, SHA_1, "PASSED", UNPINNED), "admin");
        assertThat(created.status()).isEqualTo("PLANNING");
        assertThat(jdbc.queryForObject("SELECT verdict IS NULL FROM iac_runs WHERE run_id = ?", Boolean.class,
                created.runId())).isTrue();
    }

    @Test
    void newCommitSupersedesTheOldRunAndKeepsOneFindingPerFingerprint() {
        var first = service.register(request(1, SHA_1, "PASSED", UNPINNED), "admin");
        service.uploadPlan(first.runId(), gzipResource("plan-scrubbed.json"), "admin");

        var second = service.register(request(1, SHA_2, "BLOCKED", EXEC, UNPINNED), "admin");

        assertThat(jdbc.queryForObject("SELECT status || '/' || superseded_by_run_id FROM iac_runs WHERE run_id = ?",
                String.class, first.runId())).isEqualTo("SUPERSEDED/" + second.runId());
        assertThat(jdbc.queryForObject("SELECT status FROM iac_jobs WHERE run_id = ?", String.class, first.runId()))
                .isEqualTo("CANCELLED");
        assertThat(count("iac_plan_payloads")).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_findings WHERE rule_id = 'gate.module_unpinned'",
                Long.class)).isEqualTo(1L);
        assertThat(jdbc.queryForObject("SELECT last_run_id FROM iac_findings WHERE rule_id = 'gate.module_unpinned'",
                Long.class)).isEqualTo(second.runId());
        assertThatThrownBy(() -> service.uploadPlan(first.runId(), gzipResource("plan-scrubbed.json"), "admin"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.CONFLICT));
    }

    @Test
    void findingsMissingFromTheNextRunOfTheSamePrAreFixed() {
        service.register(request(1, SHA_1, "BLOCKED", EXEC, UNPINNED), "admin");
        service.register(request(2, SHA_1, "PASSED", UNPINNED), "admin");
        service.register(request(1, SHA_2, "PASSED", UNPINNED), "admin");

        assertThat(jdbc.queryForObject("SELECT status FROM iac_findings WHERE rule_id = 'gate.exec_data_source'",
                String.class)).isEqualTo("FIXED");
        // 다른 PR 의 같은 규칙은 지문이 달라 따로 남는다
        assertThat(jdbc.queryForList("SELECT status FROM iac_findings WHERE rule_id = 'gate.module_unpinned'",
                String.class)).containsExactly("OPEN", "OPEN");
    }

    @Test
    void acceptsAScrubbedPlanAndQueuesTheAnalysis() {
        var run = service.register(request(1, SHA_1, "PASSED"), "admin");
        var accepted = service.uploadPlan(run.runId(), gzipResource("plan-scrubbed.json"), "admin");

        assertThat(accepted.status()).isEqualTo("ANALYZING");
        assertThat(jdbc.queryForObject("SELECT status FROM iac_runs WHERE run_id = ?", String.class, run.runId()))
                .isEqualTo("ANALYZING");
        assertThat(jdbc.queryForObject("SELECT kind || '/' || status FROM iac_jobs WHERE run_id = ?", String.class,
                run.runId())).isEqualTo("ANALYZE_RUN/PENDING");
        assertThat(jdbc.queryForObject("""
                SELECT expires_at BETWEEN received_at + interval '59 minutes' AND received_at + interval '61 minutes'
                FROM iac_plan_payloads WHERE run_id = ?
                """, Boolean.class, run.runId())).isTrue();
        assertThat(service.status(run.runId(), "admin").status()).isEqualTo("ANALYZING");
    }

    @Test
    void rejectsPlansThatStillCarrySecretsOrArriveAtTheWrongTime() {
        var run = service.register(request(1, SHA_1, "PASSED"), "admin");
        assertThatThrownBy(() -> service.uploadPlan(run.runId(), gzipResource("plan-raw.json"), "admin"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.UNPROCESSABLE));
        assertThat(count("iac_plan_payloads")).isZero();
        assertThat(count("iac_jobs")).isZero();

        var blocked = service.register(request(2, SHA_1, "BLOCKED", EXEC), "admin");
        assertThatThrownBy(() -> service.uploadPlan(blocked.runId(), gzipResource("plan-scrubbed.json"), "admin"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.CONFLICT));
        assertThatThrownBy(() -> service.uploadPlan(999, gzipResource("plan-scrubbed.json"), "admin"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.NOT_FOUND));
        assertThatThrownBy(() -> service.uploadPlan(run.runId(), new byte[IacPlanInspector.MAX_COMPRESSED_BYTES + 1], "admin"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.PAYLOAD_TOO_LARGE));
    }

    @Test
    void mainBranchRunsQueueADriftCheckInsteadOfPathAnalysis() {
        var push = service.register(new IacRunRequest(REPO, null, SHA_1, new IacRunRequest.Gate("PASSED", List.of()), "PUSH"), "admin");
        service.uploadPlan(push.runId(), gzipResource("plan-scrubbed.json"), "admin");
        assertThat(jdbc.queryForObject("SELECT trigger_type || '/' || coalesce(pr_number::text, '-') FROM iac_runs WHERE run_id = ?",
                String.class, push.runId())).isEqualTo("PUSH/-");
        assertThat(jdbc.queryForObject("SELECT kind FROM iac_jobs WHERE run_id = ?", String.class, push.runId()))
                .isEqualTo("CHECK_DRIFT");

        var next = service.register(new IacRunRequest(REPO, null, SHA_2, new IacRunRequest.Gate("PASSED", List.of()), "PUSH"), "admin");
        assertThat(jdbc.queryForObject("SELECT status FROM iac_runs WHERE run_id = ?", String.class, push.runId()))
                .as("다음 main 점검이 이전 점검을 대신함").isEqualTo("SUPERSEDED");
        assertThat(next.status()).isEqualTo("PLANNING");

        assertThatThrownBy(() -> service.register(new IacRunRequest(REPO, 3, SHA_1, new IacRunRequest.Gate("PASSED", List.of()), "PUSH"), "admin"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.INVALID_INPUT));
        assertThatThrownBy(() -> service.register(new IacRunRequest(REPO, null, SHA_1, new IacRunRequest.Gate("PASSED", List.of())), "admin"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.INVALID_INPUT));
    }

    @Test
    void rejectsUnknownReposRulesAndCallers() {
        assertThatThrownBy(() -> service.register(new IacRunRequest("someone/else", 1, SHA_1,
                new IacRunRequest.Gate("PASSED", List.of())), "admin"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.FORBIDDEN));
        assertThatThrownBy(() -> service.register(request(1, SHA_1, "BLOCKED", "[gate.made_up] x: y"), "admin"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.INVALID_INPUT));
        assertThatThrownBy(() -> service.register(request(1, SHA_1, "BLOCKED", "no rule id"), "admin"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.INVALID_INPUT));
        assertThatThrownBy(() -> service.register(request(1, SHA_1, "PASSED"), "someone"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.FORBIDDEN));
        assertThatThrownBy(() -> service.register(request(1, SHA_1, "PASSED"), null))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.UNAUTHENTICATED));
        assertThat(count("iac_runs")).isZero();
    }

    private static IacRunRequest request(int pr, String sha, String status, String... messages) {
        var findings = java.util.Arrays.stream(messages)
                .map(m -> new IacRunRequest.Finding(m.startsWith("[gate.module") ? "warn" : "block", m)).toList();
        return new IacRunRequest(REPO, pr, sha, new IacRunRequest.Gate(status, findings));
    }

    private static long count(String table) {
        return jdbc.queryForObject("SELECT count(*) FROM " + table, Long.class);
    }
}
