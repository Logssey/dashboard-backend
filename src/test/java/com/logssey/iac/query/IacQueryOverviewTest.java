package com.logssey.iac.query;

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

/** S-01 C·D·E·G·H 조회: PR 목록, 경로 상세의 끊을 지점, 제안 조치, plan 전 검사 관문, 검사 주기. */
class IacQueryOverviewTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final String SECRET_PATH = """
            [{"kind":"Internet","id":"internet","name":"internet"},
             {"kind":"AWSCloudFrontDistribution","id":"cf","name":"cf"},
             {"kind":"AWSLoadBalancerV2","id":"nlb","name":"logssey-prod-nlb-public"},
             {"kind":"AWSEC2Instance","id":"i-1","name":"i-1"},
             {"kind":"AWSRole","id":"role","name":"logssey-prod-role-node"},
             {"kind":"AWSSecretsManagerSecret","id":"secret","name":"rds-db"}]
            """;
    private static final String BUCKET_PATH = SECRET_PATH.replace(
            "{\"kind\":\"AWSSecretsManagerSecret\",\"id\":\"secret\",\"name\":\"rds-db\"}",
            "{\"kind\":\"AWSS3Bucket\",\"id\":\"images\",\"name\":\"logssey-prod-s3-images\"}");
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
        jdbc.update("INSERT INTO dashboard_users (login_id, password_hash, display_name, role) VALUES ('admin', 'h', 'Admin', 'ADMIN')");
        jdbc.update("INSERT INTO iac_repos (full_name, default_branch, environment) VALUES ('Logssey/infrastructure', 'main', 'PROD')");
        jdbc.update("""
                INSERT INTO iac_data_assets (arn, kind, tier) VALUES
                    ('arn:aws:secretsmanager:ap-northeast-1:1:secret:rds-db', 'SECRET', 1),
                    ('arn:aws:s3:::logssey-prod-s3-images', 'S3', 2)
                """);
        service = new IacQueryService(new IacQueryRepository(jdbc));
    }

    @Test
    void pathDetailShowsWhereThePathCanBeCut() {
        long path = path("p1", 1, SECRET_PATH);
        var detail = service.path(path, "admin");
        assertThat(detail.cutPoints()).extracting(IacPathDetailResponse.CutPoint::action)
                .containsExactly("IMDSV2_REQUIRED", "SECRETS_READ_SCOPE");
        assertThat(detail.cutPoints().getFirst().fromHop()).isEqualTo(3);
        assertThatThrownBy(() -> service.path(999, "admin"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.NOT_FOUND));
    }

    @Test
    void suggestsTheCutThatClosesTheMostPaths() {
        path("p1", 1, SECRET_PATH);
        path("p2", 1, SECRET_PATH.replace("\"i-1\"", "\"i-2\""));
        path("p3", 2, BUCKET_PATH);
        jdbc.update("INSERT INTO iac_jobs (kind, trigger_type, status, finished_at, stats) "
                + "VALUES ('CHECK_STATE', 'SCHEDULED', 'SUCCEEDED', now(), '{\"readerCount\": 5}')");

        var remediations = service.remediations("admin");
        assertThat(remediations).extracting(r -> r.action() + "|" + r.source() + "|" + r.pathsCut() + "|" + r.tier1PathsCut())
                .containsExactly("IMDSV2_REQUIRED|PATH|3|2", "SECRETS_READ_SCOPE|PATH|2|2", "TFSTATE_BUCKET_POLICY|STATE|0|0");
    }

    @Test
    void listsTheLatestRunOfEachPullRequest() {
        long old = run(58, "PR", "SUPERSEDED", null, null);
        long latest = run(58, "PR", "DONE", "BLOCK", "CRITICAL");
        run(60, "PR", "DONE", "INFO", null);
        long imds = run(62, "PR", "DONE", "WARN", "MEDIUM");
        jdbc.update("INSERT INTO iac_findings (rule_id, source, enforcement, severity, environment, resource_address, params, "
                + "fingerprint, last_run_id, first_seen_at, last_seen_at) VALUES ('path.imds_v1_added', 'PATH', 'WARN', "
                + "'MEDIUM', 'PROD', 'aws_instance.b', '{\"action\":\"CREATE\"}', 'fp-imds', ?, now(), now())", imds);
        jdbc.update("INSERT INTO iac_jobs (kind, trigger_type, run_id, status, finished_at, stats) VALUES ('ANALYZE_RUN', 'PR', ?, "
                + "'SUCCEEDED', now(), '{\"paths\":{\"added\":6,\"removed\":0,\"removedRoutes\":0},"
                + "\"state\":{\"ruleId\":\"state.reader_increase\"}}')", latest);
        jdbc.update("INSERT INTO iac_run_path_changes (run_id, change, rule_id, path_fingerprint, tier, severity, hops) "
                + "VALUES (?, 'ADDED', 'path.tier1.added', 'f', 1, 'CRITICAL', '[]')", latest);

        var prs = service.pullRequests(null, "admin");
        assertThat(prs).extracting(IacPullRequestSummaryResponse::number).containsExactlyInAnyOrder(58, 60, 62);
        assertThat(prs.stream().filter(p -> p.number() == 62).findFirst().orElseThrow().reason())
                .as("경로 없는 경로 분석 발견 건도 대표 규칙이 된다").isEqualTo("path.imds_v1_added");
        var pr58 = prs.stream().filter(p -> p.number() == 58).findFirst().orElseThrow();
        assertThat(pr58.runId()).isEqualTo(latest).isNotEqualTo(old);
        assertThat(pr58.pathsAdded()).isEqualTo(6);
        assertThat(pr58.stateReaderIncrease()).isTrue();
        assertThat(pr58.reason()).isEqualTo("path.tier1.added");
        assertThat(prs).noneMatch(p -> p.number() == 0);
    }

    @Test
    void gatesGroupMainFindingsAndRecentPullRequestBlocksByStage() {
        long main = run(null, "PUSH", "DONE", "PASS", null);
        finding("gate.provider_unpinned", "WARN", "fp-main", main);
        long blocked = run(7, "PR", "GATE_FAILED", "BLOCK", "CRITICAL");
        finding("gate.exec_data_source", "BLOCK", "fp-pr", blocked);

        var gates = service.gates(null, "admin");
        var staticCheck = gates.stages().stream().filter(s -> s.stage().equals("2")).findFirst().orElseThrow();
        assertThat(staticCheck.mainOpen()).isEqualTo(1);
        assertThat(staticCheck.prBlocked7d()).isEqualTo(1);
        assertThat(gates.supplyChain().unpinnedProviders()).isEqualTo(1);
        assertThat(gates.mainCheckedAt()).isNotNull();
    }

    @Test
    void beforeAnyRepoIsRegisteredGatesAndPullRequestsAreEmptyNotMissing() {
        jdbc.execute("TRUNCATE iac_repos RESTART IDENTITY CASCADE");

        var gates = service.gates(null, "admin");
        assertThat(gates.mainCheckedAt()).isNull();
        assertThat(gates.stages()).isNotEmpty().allMatch(s -> s.mainOpen() == 0 && s.prBlocked7d() == 0);
        assertThat(gates.supplyChain().unpinnedProviders()).isZero();
        assertThat(service.pullRequests(null, "admin")).isEmpty();
        // 지정한 레포가 없으면 여전히 404
        assertThatThrownBy(() -> service.gates("Logssey/unknown", "admin"))
                .satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(ErrorCode.NOT_FOUND));
    }

    @Test
    void jobsShowScheduleLastResultAndBacklog() {
        jdbc.update("INSERT INTO iac_jobs (kind, trigger_type, status, finished_at, last_error_code) VALUES "
                + "('ENRICH_GRAPH', 'SCHEDULED', 'FAILED', now(), 'GRAPH_UNAVAILABLE'), ('ENRICH_GRAPH', 'MANUAL', 'PENDING', NULL, NULL)");
        var jobs = service.jobs("admin");
        assertThat(jobs).extracting(IacJobStatusResponse::job)
                .containsExactly("COLLECT_GRAPH", "ENRICH_GRAPH", "CHECK_STATE", "CHECK_DRIFT", "ANALYZE_RUN");
        var enrich = jobs.get(1);
        assertThat(enrich.lastStatus()).isEqualTo("FAILED");
        assertThat(enrich.lastErrorCode()).isEqualTo("GRAPH_UNAVAILABLE");
        assertThat(enrich.pending()).isEqualTo(1);
        assertThat(jobs.getFirst().lastFinishedAt()).isNull();
    }

    private static long path(String fingerprint, int tier, String hops) {
        return jdbc.queryForObject("""
                INSERT INTO iac_attack_paths (fingerprint, entry, target_data_asset_id, tier, severity, environment,
                                              hops, length, status, first_seen_at, last_seen_at)
                VALUES (?, 'internet', ?, ?, ?, 'PROD', ?::jsonb, 5, 'OPEN', now(), now()) RETURNING path_id
                """, Long.class, fingerprint, tier, tier, tier == 1 ? "CRITICAL" : "HIGH", hops);
    }

    private static long run(Integer pr, String trigger, String status, String verdict, String severity) {
        return jdbc.queryForObject("""
                INSERT INTO iac_runs (repo_id, pr_number, head_sha, trigger_type, status, verdict, highest_severity)
                VALUES (1, ?, repeat('a', 40), ?, ?, ?, ?) RETURNING run_id
                """, Long.class, pr, trigger, status, verdict, severity);
    }

    private static void finding(String rule, String enforcement, String fingerprint, long runId) {
        jdbc.update("""
                INSERT INTO iac_findings (rule_id, source, enforcement, severity, environment, resource_address,
                                          fingerprint, last_run_id, first_seen_at, last_seen_at)
                VALUES (?, 'GATE', ?, 'HIGH', 'PROD', 'x', ?, ?, now(), now())
                """, rule, enforcement, fingerprint, runId);
    }
}
