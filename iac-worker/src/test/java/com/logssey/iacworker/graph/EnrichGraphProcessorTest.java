package com.logssey.iacworker.graph;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Duration;
import java.util.List;
import java.util.Map;

import com.logssey.iacworker.IacJobExecutionService;
import com.logssey.iacworker.IacJobFailure;
import com.logssey.iacworker.IacJobFailureCode;
import com.logssey.iacworker.IacJobKind;
import com.logssey.iacworker.IacJobProperties;
import com.logssey.iacworker.IacJobTestSupport;

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
import software.amazon.awssdk.core.exception.SdkClientException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** S3 10/19 검증: 대표 경로 "인터넷 → CloudFront → NLB → 노드 → 노드 역할 → 시크릿" 이 열린 경로로 저장된다. */
class EnrichGraphProcessorTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final Neo4jContainer NEO4J = new Neo4jContainer("neo4j:5.26.30-community").withAdminPassword("test-password");
    private static final String MAIN = "arn:aws:cloudfront::111122223333:distribution/MAIN";
    private static final String OFF = "arn:aws:cloudfront::111122223333:distribution/OFF";
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
            session.run(resource("/graph/cartography-fixture.cypher")).consume();
        }
        jdbc.execute("TRUNCATE iac_attack_paths, iac_data_assets, iac_jobs, iac_audit_events RESTART IDENTITY CASCADE");
        jdbc.update("""
                INSERT INTO iac_data_assets (arn, kind, tier) VALUES
                    ('arn:aws:secretsmanager:ap-northeast-1:111122223333:secret:rds-db-AbCdEf', 'SECRET', 1),
                    ('arn:aws:s3:::logssey-prod-s3-tfstate', 'TFSTATE', 1),
                    ('arn:aws:s3:::logssey-prod-s3-images', 'S3', 2)
                """);
        execution = IacJobTestSupport.execution(jdbc, properties(), transactions);
    }

    @Test
    void storesPathsFromTheInternetThroughCloudFrontToTieredData() {
        run(processor(Map.of("worker-1", "10.20.10.20")));

        assertThat(jdbc.queryForList("""
                SELECT tier || '|' || severity || '|' || length || '|' ||
                       (SELECT string_agg(h ->> 'kind', '>' ORDER BY o) FROM jsonb_array_elements(hops) WITH ORDINALITY x(h, o))
                FROM iac_attack_paths WHERE status = 'OPEN' ORDER BY tier
                """, String.class)).containsExactly(
                "1|CRITICAL|5|Internet>AWSCloudFrontDistribution>AWSLoadBalancerV2>AWSEC2Instance>AWSRole>AWSSecretsManagerSecret",
                "2|HIGH|5|Internet>AWSCloudFrontDistribution>AWSLoadBalancerV2>AWSEC2Instance>AWSRole>AWSS3Bucket");
        // IMDSv2 인스턴스·내부 LB 뒤 인스턴스·꺼진 배포·등급 없는 버킷·읽을 수 없는 tfstate 는 경로가 아니다
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_attack_paths WHERE hops::text LIKE '%i-worker2%' "
                + "OR hops::text LIKE '%i-cp1%' OR hops::text LIKE '%/OFF%'", Long.class)).isZero();
        assertThat(graphCount("MATCH (:AWSEC2Instance {id: 'i-worker2'})-[r:HAS_CREDS_OF]->() RETURN count(r) AS n"))
                .as("지난 실행의 관계는 다시 확인되지 않아 지워짐").isZero();
        assertThat(graphCount("MATCH (:KubernetesNode {name: 'worker-1'})-[r:IS_INSTANCE {_source: 'logssey'}]->"
                + "(:AWSEC2Instance {id: 'i-worker1'}) RETURN count(r) AS n")).isEqualTo(1);
        assertThat(graphCount("MATCH (n {id: 'logssey-prod-s3-tfstate'}) RETURN n.logssey_tier AS n")).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT after_safe ->> 'openPaths' FROM iac_audit_events WHERE event_type = 'GRAPH_ENRICHED'",
                String.class)).isEqualTo("2");
    }

    @Test
    void closesPathsThatNoLongerExistAndKeepsFingerprintsStable() {
        var processor = processor(Map.of());
        run(processor);
        var fingerprints = jdbc.queryForList("SELECT fingerprint FROM iac_attack_paths ORDER BY fingerprint", String.class);

        run(processor);
        assertThat(jdbc.queryForList("SELECT fingerprint FROM iac_attack_paths ORDER BY fingerprint", String.class))
                .isEqualTo(fingerprints);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_attack_paths WHERE status = 'OPEN'", Long.class))
                .isEqualTo(2L);

        // IMDSv2 를 강제하면 경로가 끊긴다
        try (var session = driver.session()) {
            session.run("MATCH (e:AWSEC2Instance {id: 'i-worker1'}) SET e.metadatahttptokens = 'required'").consume();
        }
        run(processor);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_attack_paths WHERE status = 'CLOSED'", Long.class))
                .isEqualTo(2L);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_attack_paths WHERE status = 'OPEN'", Long.class)).isZero();
    }

    @Test
    void reachesAnInternetFacingBalancerDirectlyOnlyWhenItsListenerIsOpenToTheWorld() {
        run(processor(Map.of()));
        assertThat(graphCount("MATCH (:LogsseyInternet)-[r:CAN_REACH]->(:AWSLoadBalancerV2) RETURN count(r) AS n")).isZero();

        try (var session = driver.session()) {
            session.run("""
                    MATCH (sg:AWSEC2SecurityGroup {id: 'sg-public-nlb'}), (anywhere:AWSIpRange {id: '0.0.0.0/0'})
                    CREATE (rule:AWSIpPermissionInbound:IpPermissionInbound:IpRule {id: 'sg-public-nlb/in/443', protocol: 'tcp', fromport: 443, toport: 443})
                    CREATE (rule)-[:MEMBER_OF_EC2_SECURITY_GROUP]->(sg)
                    CREATE (anywhere)-[:MEMBER_OF_IP_RULE]->(rule)
                    """).consume();
        }
        run(processor(Map.of()));
        assertThat(graphCount("MATCH (:LogsseyInternet)-[r:CAN_REACH {port: 443}]->(:AWSLoadBalancerV2 {id: 'nlb-public'}) "
                + "RETURN count(r) AS n")).isEqualTo(1);
        // 직접 가는 짧은 경로가 따로 생긴다 (4 홉)
        assertThat(jdbc.queryForList("SELECT DISTINCT length FROM iac_attack_paths WHERE status = 'OPEN' ORDER BY length",
                Integer.class)).containsExactly(4, 5);
    }

    @Test
    void cloudFrontOutagesAreRetryableAndWriteNothing() {
        var processor = new EnrichGraphProcessor(new GraphEnricher(driver), () -> {
            throw SdkClientException.create("unreachable");
        }, Map::of, new AttackPathRepository(jdbc));
        long jobId = job();
        var claimed = execution.claimNextJob(IacJobKind.ENRICH_GRAPH).orElseThrow();
        assertThatThrownBy(() -> processor.process(claimed, execution))
                .isInstanceOf(IacJobFailure.class)
                .satisfies(e -> assertThat(((IacJobFailure) e).code()).isEqualTo(IacJobFailureCode.AWS_UNAVAILABLE))
                .satisfies(e -> assertThat(((IacJobFailure) e).retryable()).isTrue());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_attack_paths", Long.class)).isZero();
        assertThat(jobId).isPositive();
    }

    private void run(EnrichGraphProcessor processor) {
        job();
        var claimed = execution.claimNextJob(IacJobKind.ENRICH_GRAPH).orElseThrow();
        processor.process(claimed, execution);
        assertThat(execution.complete(claimed.jobId(), claimed.leaseToken())).isTrue();
    }

    private static EnrichGraphProcessor processor(Map<String, String> nodes) {
        return new EnrichGraphProcessor(new GraphEnricher(driver),
                () -> List.of(new CloudFrontOrigins.Origin(MAIN, "origin.re-used.store"),
                        new CloudFrontOrigins.Origin(OFF, "origin.re-used.store")),
                () -> nodes, new AttackPathRepository(jdbc));
    }

    private static long job() {
        return jdbc.queryForObject("INSERT INTO iac_jobs (kind, trigger_type) VALUES ('ENRICH_GRAPH', 'SCHEDULED') "
                + "RETURNING job_id", Long.class);
    }

    private static long graphCount(String query) {
        try (var session = driver.session()) {
            return session.run(query).single().get("n").asLong(0);
        }
    }

    private static IacJobProperties properties() {
        return new IacJobProperties(true, Duration.ofSeconds(1), Duration.ofMinutes(5), 10,
                Duration.ofSeconds(30), Duration.ofMinutes(30), Duration.ofMinutes(5));
    }

    private static String resource(String name) {
        try (var in = EnrichGraphProcessorTest.class.getResourceAsStream(name)) {
            return new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
