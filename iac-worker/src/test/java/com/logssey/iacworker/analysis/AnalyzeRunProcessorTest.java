package com.logssey.iacworker.analysis;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.logssey.iacworker.IacJobExecutionService;
import com.logssey.iacworker.IacJobFailure;
import com.logssey.iacworker.IacJobFailureCode;
import com.logssey.iacworker.IacJobKind;
import com.logssey.iacworker.IacJobProperties;
import com.logssey.iacworker.IacJobTestSupport;
import com.logssey.iacworker.graph.AttackPathRepository;
import com.logssey.iacworker.graph.CloudFrontOrigins;
import com.logssey.iacworker.graph.EnrichGraphProcessor;
import com.logssey.iacworker.graph.GraphEnricher;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.neo4j.Neo4jContainer;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * S3 10/20 검증: CI 가 실제 PR 에서 만든 plan(민감값 제거)으로
 * #58 은 차단, IMDSv2 강제는 경로 감소, 변경 없음은 발견 0.
 */
class AnalyzeRunProcessorTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final Neo4jContainer NEO4J = new Neo4jContainer("neo4j:5.26.30-community").withAdminPassword("test-password");
    private static final String CLOUDFRONT = "arn:aws:cloudfront::794386801311:distribution/EYTWHIBCVO5FY";
    private static final JsonMapper MAPPER = JsonMapper.builder().build();
    private static JdbcTemplate jdbc;
    private static DataSourceTransactionManager transactions;
    private static Driver driver;
    private IacJobExecutionService execution;

    @BeforeAll
    static void start() {
        POSTGRES.start();
        NEO4J.start();
        var datasource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(datasource).load().migrate();
        jdbc = new JdbcTemplate(datasource);
        transactions = new DataSourceTransactionManager(datasource);
        driver = GraphDatabase.driver(NEO4J.getBoltUrl(), AuthTokens.basic("neo4j", "test-password"));
    }

    @AfterAll
    static void stop() {
        driver.close();
        NEO4J.stop();
        POSTGRES.stop();
    }

    @BeforeEach
    void reset() {
        try (var session = driver.session()) {
            session.run("MATCH (n) DETACH DELETE n").consume();
            session.run(text("/graph/prod-like-fixture.cypher")).consume();
        }
        jdbc.execute("TRUNCATE iac_run_path_changes, iac_attack_paths, iac_data_assets, iac_jobs, iac_runs, iac_repos, "
                + "iac_audit_events RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO iac_repos (full_name, default_branch, environment) VALUES ('Logssey/infrastructure', 'main', 'PROD')");
        jdbc.update("""
                INSERT INTO iac_data_assets (arn, kind, tier) VALUES
                    ('arn:aws:s3:::logssey-prod-s3-tfstate', 'TFSTATE', 1),
                    ('arn:aws:secretsmanager:ap-northeast-1:794386801311:secret:reused/prod/api-ONfjwj', 'SECRET', 1),
                    ('arn:aws:s3:::logssey-prod-s3-images', 'S3', 2)
                """);
        execution = IacJobTestSupport.execution(jdbc, properties(), transactions);
        // 매일 보강으로 지금 열린 경로를 만든다 (워커 3대 × 시크릿·이미지 = 6)
        new EnrichGraphProcessor(new GraphEnricher(driver), () -> List.of(new CloudFrontOrigins.Origin(CLOUDFRONT,
                "origin.re-used.store")), Map::of, new AttackPathRepository(jdbc)).process(claim(job("ENRICH_GRAPH", null)), execution);
        assertThat(count("iac_attack_paths WHERE status = 'OPEN'")).isEqualTo(6);
    }

    @Test
    void pr58RemovingTheTfstateDenyIsBlockedAfterTheSimulatorConfirmsIt() {
        long run = analyze("58.json.gz", policySimulator());

        assertThat(jdbc.queryForObject("SELECT status || '/' || verdict || '/' || highest_severity FROM iac_runs WHERE run_id = ?",
                String.class, run)).isEqualTo("DONE/BLOCK/CRITICAL");
        assertThat(jdbc.queryForList("""
                SELECT change || '|' || rule_id || '|' || severity || '|' || cause_address || '|' ||
                       (evidence ->> 'causeAction') || '|' || (evidence #>> '{simulator,before}') || '>' || (evidence #>> '{simulator,after}') || '|' ||
                       (hops -> -1 ->> 'name')
                FROM iac_run_path_changes WHERE run_id = ? ORDER BY change_id
                """, String.class, run)).hasSize(3).containsOnly(
                "ADDED|path.tier1.added|CRITICAL|module.iam.aws_iam_role_policy.deny_tfstate|DELETE|explicitDeny>allowed|logssey-prod-s3-tfstate");
        assertThat(jdbc.queryForObject("SELECT stats -> 'resources' ->> 'delete' FROM iac_jobs WHERE kind = 'ANALYZE_RUN'",
                String.class)).isEqualTo("1");
        assertThat(count("iac_plan_payloads")).as("분석이 끝나면 plan 은 남지 않는다 (SR-5)").isZero();
    }

    @Test
    void enforcingImdsV2RemovesTheOpenRouteThroughTheNodeRole() {
        long run = analyze("imdsv2.json.gz", policySimulator());

        assertThat(jdbc.queryForObject("SELECT verdict FROM iac_runs WHERE run_id = ?", String.class, run)).isEqualTo("INFO");
        assertThat(jdbc.queryForList("""
                SELECT DISTINCT change || '|' || rule_id || '|' || (path_id IS NOT NULL) || '|' || (evidence ->> 'causeAction')
                FROM iac_run_path_changes WHERE run_id = ?
                """, String.class, run)).containsExactly("REMOVED|path.removed|true|UPDATE");
        assertThat(count("iac_run_path_changes WHERE change = 'REMOVED'")).isEqualTo(6);
        assertThat(jdbc.queryForObject("SELECT stats -> 'paths' ->> 'removedRoutes' FROM iac_jobs WHERE kind = 'ANALYZE_RUN'",
                String.class)).as("노드 역할로 가는 한 갈래가 사라짐 (경로 -1)").isEqualTo("1");
        assertThat(jdbc.queryForObject("SELECT stats -> 'resources' ->> 'change' FROM iac_jobs WHERE kind = 'ANALYZE_RUN'",
                String.class)).isEqualTo("10");
    }

    @Test
    void currentRepositoryWithoutChangesHasNoFindings() {
        long run = analyze("nochange.json.gz", policySimulator());
        assertThat(jdbc.queryForObject("SELECT verdict FROM iac_runs WHERE run_id = ?", String.class, run)).isEqualTo("PASS");
        assertThat(count("iac_run_path_changes")).isZero();
    }

    @Test
    void tierOneAdditionTheSimulatorDoesNotConfirmIsOnlyAWarning() {
        long run = analyze("58.json.gz", (documents, action, resource) -> "implicitDeny");
        assertThat(jdbc.queryForObject("SELECT verdict || '/' || highest_severity FROM iac_runs WHERE run_id = ?",
                String.class, run)).isEqualTo("WARN/HIGH");
    }

    @Test
    void simulatorOutageIsRetryableAndMissingPlansFailTheRun() {
        long run = run("ANALYZING");
        jdbc.update("INSERT INTO iac_plan_payloads (run_id, content, size_bytes, expires_at) VALUES (?, ?, 1, now() + interval '1 hour')",
                run, resource("/plans/58.json.gz"));
        var claimed = claim(job("ANALYZE_RUN", run));
        assertThatThrownBy(() -> processor((d, a, r) -> {
            throw software.amazon.awssdk.core.exception.SdkClientException.create("unreachable");
        }).process(claimed, execution))
                .satisfies(e -> assertThat(((IacJobFailure) e).code()).isEqualTo(IacJobFailureCode.SIMULATOR_UNAVAILABLE))
                .satisfies(e -> assertThat(((IacJobFailure) e).retryable()).isTrue());
        assertThat(count("iac_run_path_changes")).isZero();

        long missing = run("ANALYZING");
        var noPlan = claim(job("ANALYZE_RUN", missing));
        assertThatThrownBy(() -> processor(policySimulator()).process(noPlan, execution))
                .satisfies(e -> assertThat(((IacJobFailure) e).code()).isEqualTo(IacJobFailureCode.PLAN_MISSING))
                .satisfies(e -> assertThat(((IacJobFailure) e).retryable()).isFalse());
    }

    @Test
    void loadsTheGraphSnapshot() {
        var graph = new GraphLoader(driver).load();
        assertThat(graph.instances()).hasSize(3);
        assertThat(graph.roles().get("arn:aws:iam::794386801311:role/logssey-prod-role-node").policies()).hasSize(4);
        assertThat(graph.managed()).containsKey("arn:aws:iam::aws:policy/AmazonS3FullAccess");
    }

    @Test
    void supersededRunsAreSkipped() {
        long run = run("SUPERSEDED");
        processor(policySimulator()).process(claim(job("ANALYZE_RUN", run)), execution);
        assertThat(jdbc.queryForObject("SELECT status FROM iac_runs WHERE run_id = ?", String.class, run)).isEqualTo("SUPERSEDED");
        assertThat(count("iac_run_path_changes")).isZero();
    }

    private long analyze(String plan, IamSimulator simulator) {
        long run = run("ANALYZING");
        jdbc.update("INSERT INTO iac_plan_payloads (run_id, content, size_bytes, expires_at) VALUES (?, ?, ?, now() + interval '1 hour')",
                run, resource("/plans/" + plan), resource("/plans/" + plan).length);
        var claimed = claim(job("ANALYZE_RUN", run));
        processor(simulator).process(claimed, execution);
        assertThat(execution.complete(claimed.jobId(), claimed.leaseToken())).isTrue();
        return run;
    }

    private static AnalyzeRunProcessor processor(IamSimulator simulator) {
        return new AnalyzeRunProcessor(new GraphLoader(driver), new AnalysisEngine(simulator), new AnalyzeRunRepository(jdbc));
    }

    /** 문서를 같은 IAM 규칙으로 평가해 EvalDecision 을 돌려주는 시뮬레이터 대역. */
    private static IamSimulator policySimulator() {
        return (documents, action, resource) -> {
            List<Policy> policies = new ArrayList<>();
            for (String document : documents) {
                List<PolicyStatement> statements = new ArrayList<>();
                for (JsonNode s : MAPPER.readTree(document).path("Statement")) {
                    statements.add(new PolicyStatement(s.path("Effect").asString(), list(s.path("Action")),
                            list(s.path("NotAction")), list(s.path("Resource")), list(s.path("NotResource")), null));
                }
                policies.add(new Policy("doc", "doc", statements));
            }
            boolean denied = policies.stream().flatMap(p -> p.statements().stream())
                    .anyMatch(s -> "Deny".equals(s.effect()) && PolicyEvaluator.matches(s, action, resource));
            if (denied) return "explicitDeny";
            return PolicyEvaluator.allows(policies, action, resource) ? "allowed" : "implicitDeny";
        };
    }

    private static List<String> list(JsonNode node) {
        List<String> values = new ArrayList<>();
        if (node.isArray()) node.forEach(v -> values.add(v.asString()));
        else if (node.isString()) values.add(node.asString());
        return values;
    }

    private com.logssey.iacworker.ClaimedIacJob claim(long jobId) {
        String kind = jdbc.queryForObject("SELECT kind FROM iac_jobs WHERE job_id = ?", String.class, jobId);
        return execution.claimNextJob(IacJobKind.valueOf(kind)).orElseThrow();
    }

    private static long job(String kind, Long runId) {
        return jdbc.queryForObject("INSERT INTO iac_jobs (kind, trigger_type, run_id) VALUES (?, 'PR', ?) RETURNING job_id",
                Long.class, kind, runId);
    }

    private static long run(String status) {
        return jdbc.queryForObject("""
                INSERT INTO iac_runs (repo_id, pr_number, head_sha, trigger_type, status)
                VALUES (1, 58, repeat('a', 40), 'PR', ?) RETURNING run_id
                """, Long.class, status);
    }

    private static long count(String tableAndWhere) {
        return jdbc.queryForObject("SELECT count(*) FROM " + tableAndWhere, Long.class);
    }

    private static IacJobProperties properties() {
        return new IacJobProperties(true, Duration.ofSeconds(1), Duration.ofMinutes(5), 10,
                Duration.ofSeconds(30), Duration.ofMinutes(30), Duration.ofMinutes(5));
    }

    private static byte[] resource(String name) {
        try (var in = AnalyzeRunProcessorTest.class.getResourceAsStream(name)) {
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String text(String name) {
        return new String(resource(name), StandardCharsets.UTF_8);
    }
}
