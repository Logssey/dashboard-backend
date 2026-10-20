package com.logssey.iacworker.state;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;

import com.logssey.iacworker.IacJobExecutionService;
import com.logssey.iacworker.IacJobKind;
import com.logssey.iacworker.IacJobProperties;
import com.logssey.iacworker.IacJobTestSupport;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.neo4j.driver.AuthTokens;
import org.neo4j.driver.Driver;
import org.neo4j.driver.GraphDatabase;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.neo4j.Neo4jContainer;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;

class CheckStateProcessorTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final Neo4jContainer NEO4J = new Neo4jContainer("neo4j:5.26.30-community").withAdminPassword("test-password");
    private static JdbcTemplate jdbc;
    private static Driver driver;
    private static IacJobExecutionService execution;

    @BeforeAll
    static void start() throws IOException {
        POSTGRES.start();
        NEO4J.start();
        var datasource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(datasource).load().migrate();
        jdbc = new JdbcTemplate(datasource);
        execution = IacJobTestSupport.execution(jdbc, new IacJobProperties(true, Duration.ofSeconds(1),
                Duration.ofMinutes(5), 10, Duration.ofSeconds(30), Duration.ofMinutes(30), Duration.ofMinutes(5)),
                new DataSourceTransactionManager(datasource));
        driver = GraphDatabase.driver(NEO4J.getBoltUrl(), AuthTokens.basic("neo4j", "test-password"));
        try (var in = CheckStateProcessorTest.class.getResourceAsStream("/graph/prod-like-fixture.cypher");
             var session = driver.session()) {
            session.run(new String(in.readAllBytes(), StandardCharsets.UTF_8)).consume();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        jdbc.update("INSERT INTO iac_data_assets (arn, kind, tier) VALUES ('arn:aws:s3:::logssey-prod-s3-tfstate', 'TFSTATE', 1)");
    }

    @AfterAll
    static void stop() {
        driver.close();
        NEO4J.stop();
        POSTGRES.stop();
    }

    @Test
    void recordsWhoCanReadTheStateBucket() {
        jdbc.update("INSERT INTO iac_jobs (kind, trigger_type) VALUES ('CHECK_STATE', 'SCHEDULED')");
        var claimed = execution.claimNextJob(IacJobKind.CHECK_STATE).orElseThrow();
        new CheckStateProcessor(new StateReaders(driver), jdbc).process(claimed, execution);
        assertThat(execution.complete(claimed.jobId(), claimed.leaseToken())).isTrue();

        assertThat(jdbc.queryForObject("SELECT stats ->> 'readerCount' FROM iac_jobs WHERE job_id = ?", String.class,
                claimed.jobId())).isEqualTo("2");
        assertThat(jdbc.queryForList("""
                SELECT r ->> 'kind' || ':' || (r ->> 'name')
                FROM iac_jobs, jsonb_array_elements(stats -> 'tfstate' -> 0 -> 'readers') r WHERE job_id = ?
                """, String.class, claimed.jobId())).containsExactly("AWSUser:dahyeon", "AWSUser:jongmin");
        assertThat(jdbc.queryForObject("SELECT stats -> 'tfstate' -> 0 ->> 'name' FROM iac_jobs WHERE job_id = ?",
                String.class, claimed.jobId())).isEqualTo("logssey-prod-s3-tfstate");
    }
}
