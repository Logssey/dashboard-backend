package com.logssey.iac.query;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.common.error.GlobalExceptionHandler;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class IacQueryServiceTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final String HOPS = """
            [{"kind":"Internet","id":"internet","name":"internet"},
             {"kind":"AWSRole","id":"arn:aws:iam::1:role/node","name":"logssey-prod-role-node"},
             {"kind":"AWSS3Bucket","id":"arn:aws:s3:::logssey-prod-s3-tfstate","name":"logssey-prod-s3-tfstate"}]
            """;
    private static JdbcTemplate jdbc;
    private IacQueryService service;

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
    void reset() {
        jdbc.execute("TRUNCATE iac_run_path_changes, iac_attack_paths, iac_findings, iac_jobs, iac_runs, iac_repos, "
                + "iac_data_assets, dashboard_users RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO dashboard_users (login_id, password_hash, display_name, role) "
                + "VALUES ('admin', 'h', 'Admin', 'ADMIN')");
        jdbc.update("INSERT INTO iac_repos (full_name, default_branch, environment) VALUES ('Logssey/infrastructure', 'main', 'PROD')");
        jdbc.update("""
                INSERT INTO iac_data_assets (arn, kind, tier) VALUES
                    ('arn:aws:secretsmanager:ap-northeast-1:1:secret:db', 'SECRET', 1),
                    ('arn:aws:s3:::logssey-prod-s3-images', 'S3', 2)
                """);
        service = new IacQueryService(new IacQueryRepository(jdbc));
    }

    @Test
    void summaryCountsOpenPathsAndDailyFindingsButNotPullRequestResults() {
        path("p1", 1, "CRITICAL", "OPEN");
        path("p2", 1, "CRITICAL", "OPEN");
        path("p3", 2, "HIGH", "OPEN");
        path("p4", 1, "CRITICAL", "CLOSED");
        long daily = job("ENRICH_GRAPH", "SUCCEEDED", "now() - interval '1 hour'");
        long run = run(1, "GATE_FAILED", "BLOCK", "CRITICAL");
        finding("fp-daily", "MEDIUM", null, daily);
        finding("fp-pr", "CRITICAL", run, null);
        job("COLLECT_GRAPH", "SUCCEEDED", "now() - interval '30 hours'");

        var summary = service.summary("admin");

        assertThat(summary.metrics().tier1OpenPaths()).isEqualTo(2);
        assertThat(summary.metrics().openPaths()).isEqualTo(3);
        assertThat(summary.metrics().drifts()).isNull();
        assertThat(summary.severityCounts()).containsEntry("CRITICAL", 2L).containsEntry("HIGH", 1L)
                .containsEntry("MEDIUM", 1L).containsEntry("LOW", 0L);
        assertThat(summary.lastFullCheckAt()).isNotNull();
        assertThat(summary.graphStale()).isTrue();
    }

    @Test
    void pathsArePagedByCursorAndFilteredByTier() {
        for (int i = 0; i < 5; i++) path("t1-" + i, 1, "CRITICAL", "OPEN");
        path("t2", 2, "HIGH", "OPEN");

        var first = service.paths("OPEN", 1, null, 2, "admin");
        var second = service.paths("OPEN", 1, first.nextCursor(), 2, "admin");
        var last = service.paths("OPEN", 1, second.nextCursor(), 2, "admin");

        assertThat(first.items()).hasSize(2);
        assertThat(second.items()).hasSize(2);
        assertThat(last.items()).hasSize(1);
        assertThat(last.nextCursor()).isNull();
        assertThat(first.items().getFirst().target().kind()).isEqualTo("SECRET");
        assertThat(first.items().getFirst().hops().get(1).get("name").asString()).isEqualTo("logssey-prod-role-node");
        assertThatThrownBy(() -> service.paths("BOGUS", null, null, 20, "admin"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.INVALID_INPUT));
        assertThatThrownBy(() -> service.paths("OPEN", null, null, 101, "admin"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.INVALID_INPUT));
    }

    @Test
    void pullRequestShowsTheLatestRunWithItsGateFindingsAndPathChanges() throws Exception {
        long old = run(58, "SUPERSEDED", null, null);
        long latest = run(58, "DONE", "BLOCK", "CRITICAL");
        finding("fp-old", "HIGH", old, null);
        jdbc.update("""
                INSERT INTO iac_run_path_changes (run_id, change, rule_id, path_fingerprint, tier, severity, hops,
                                                  cause_address, evidence)
                VALUES (?, 'ADDED', 'path.tier1.added', 'new-path', 1, 'CRITICAL', ?::jsonb,
                        'module.iam.aws_iam_role_policy.deny_tfstate',
                        '{"causeAction":"DELETE","simulator":{"before":"explicitDeny","after":"allowed"}}'),
                       (?, 'REMOVED', 'path.removed', 'old-path', 2, NULL, ?::jsonb, NULL, NULL)
                """, latest, HOPS, latest, HOPS);
        jdbc.update("INSERT INTO iac_jobs (kind, trigger_type, run_id, status, stats) "
                + "VALUES ('ANALYZE_RUN', 'PR', ?, 'SUCCEEDED', '{\"resources\":{\"add\":0,\"change\":0,\"delete\":1},"
                + "\"state\":{\"ruleId\":\"state.reader_increase\",\"severity\":\"HIGH\",\"readersBefore\":5,"
                + "\"readersAfter\":6,\"secretsAdded\":0}}')", latest);

        var pr = service.pullRequest(58, null, "admin");
        assertThat(pr.runId()).isEqualTo(latest);
        assertThat(pr.gate().status()).isEqualTo("PASS");
        assertThat(pr.gate().findings()).isEmpty();
        assertThat(pr.paths()).extracting(IacPullRequestResponse.PathChange::change).containsExactly("ADDED", "REMOVED");
        assertThat(pr.paths().getFirst().cause().action()).isEqualTo("DELETE");
        assertThat(pr.paths().getFirst().evidence().has("causeAction")).isFalse();
        assertThat(pr.resources().get("delete").asInt()).isEqualTo(1);
        assertThat(pr.state().get("readersAfter").asInt()).isEqualTo(6);

        // 같은 응답이 계약 모양으로 직렬화되는지
        var mvc = MockMvcBuilders.standaloneSetup(new IacQueryController(service))
                .setControllerAdvice(new GlobalExceptionHandler()).build();
        mvc.perform(get("/api/v1/iac/prs/58").principal(new UsernamePasswordAuthenticationToken("admin", "n/a")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verdict").value("BLOCK"))
                .andExpect(jsonPath("$.paths[0].ruleId").value("path.tier1.added"))
                .andExpect(jsonPath("$.paths[0].hops[2].name").value("logssey-prod-s3-tfstate"))
                .andExpect(jsonPath("$.paths[0].evidence.simulator.after").value("allowed"))
                .andExpect(jsonPath("$.paths[0].cause.address").value("module.iam.aws_iam_role_policy.deny_tfstate"))
                .andExpect(jsonPath("$.resources.delete").value(1))
                .andExpect(jsonPath("$.state.ruleId").value("state.reader_increase"))
                .andExpect(jsonPath("$.state.readersBefore").value(5));
        mvc.perform(get("/api/v1/iac/prs/59").principal(new UsernamePasswordAuthenticationToken("admin", "n/a")))
                .andExpect(status().isNotFound());
    }

    @Test
    void stateSummaryShowsTheLatestStateCheck() {
        assertThat(service.stateSummary("admin").checkedAt()).isNull();
        jdbc.update("""
                INSERT INTO iac_jobs (kind, trigger_type, status, finished_at, stats) VALUES
                    ('CHECK_STATE', 'SCHEDULED', 'SUCCEEDED', now() - interval '2 days', '{"readerCount": 5, "tfstate": []}'),
                    ('CHECK_STATE', 'SCHEDULED', 'SUCCEEDED', now(),
                     '{"readerCount": 6, "tfstate": [{"arn": "arn:aws:s3:::logssey-prod-s3-tfstate", "name": "logssey-prod-s3-tfstate",
                       "readers": [{"kind": "AWSUser", "name": "jongmin"}]}]}')
                """);
        var state = service.stateSummary("admin");
        assertThat(state.readerCount()).isEqualTo(6);
        assertThat(state.tfstate().get(0).get("readers").get(0).get("name").asString()).isEqualTo("jongmin");
        assertThat(state.sensitiveActual()).isNull();
    }

    @Test
    void blockedPullRequestListsItsGateFindings() {
        long run = run(7, "GATE_FAILED", "BLOCK", "CRITICAL");
        finding("fp-gate", "CRITICAL", run, null);
        var pr = service.pullRequest(7, "Logssey/infrastructure", "admin");
        assertThat(pr.gate().status()).isEqualTo("BLOCK");
        assertThat(pr.gate().findings()).extracting(IacPullRequestResponse.GateFinding::address)
                .containsExactly("data.external.x");
        assertThat(pr.resources()).isNull();
        assertThat(pr.state()).isNull();
    }

    @Test
    void asksForTheRepoWhenThereIsMoreThanOneAndRejectsNonAdmins() {
        jdbc.update("INSERT INTO iac_repos (full_name, default_branch, environment) VALUES ('Logssey/other', 'main', 'DEV')");
        run(1, "PLANNING", null, null);
        assertThatThrownBy(() -> service.pullRequest(1, null, "admin"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.INVALID_INPUT));
        assertThat(service.pullRequest(1, "Logssey/infrastructure", "admin").status()).isEqualTo("PLANNING");
        assertThatThrownBy(() -> service.summary("someone"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.FORBIDDEN));
    }

    private static void path(String fingerprint, int tier, String severity, String status) {
        jdbc.update("""
                INSERT INTO iac_attack_paths (fingerprint, entry, target_data_asset_id, tier, severity, environment,
                                              hops, length, status, first_seen_at, last_seen_at)
                VALUES (?, 'internet', ?, ?, ?, 'PROD', ?::jsonb, 2, ?, now(), now())
                """, fingerprint, tier, tier, severity, HOPS, status);
    }

    private static long job(String kind, String status, String finishedAtSql) {
        return jdbc.queryForObject("INSERT INTO iac_jobs (kind, trigger_type, status, finished_at) "
                + "VALUES (?, 'SCHEDULED', ?, " + finishedAtSql + ") RETURNING job_id", Long.class, kind, status);
    }

    private static long run(int pr, String status, String verdict, String severity) {
        return jdbc.queryForObject("""
                INSERT INTO iac_runs (repo_id, pr_number, head_sha, trigger_type, status, verdict, highest_severity)
                VALUES (1, ?, repeat('a', 40), 'PR', ?, ?, ?) RETURNING run_id
                """, Long.class, pr, status, verdict, severity);
    }

    private static void finding(String fingerprint, String severity, Long runId, Long jobId) {
        jdbc.update("""
                INSERT INTO iac_findings (rule_id, source, enforcement, severity, environment, resource_address,
                                          fingerprint, last_run_id, last_job_id, first_seen_at, last_seen_at)
                VALUES ('gate.exec_data_source', 'GATE', 'BLOCK', ?, 'PROD', 'data.external.x', ?, ?, ?, now(), now())
                """, severity, fingerprint, runId, jobId);
    }
}
