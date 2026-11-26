package com.logssey.iacworker.drift;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Duration;

import com.logssey.iacworker.IacJobExecutionService;
import com.logssey.iacworker.IacJobKind;
import com.logssey.iacworker.IacJobProperties;
import com.logssey.iacworker.IacJobTestSupport;

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

/** U4: 콘솔에서 바뀐 DNS 레코드를 매일 점검이 "높음" 으로 잡고, 되돌리면 고쳐진 것으로 닫는다. 현재 레포는 노이즈만 있어 0. */
class CheckDriftProcessorTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static JdbcTemplate jdbc;
    private static IacJobExecutionService execution;

    @BeforeAll
    static void start() {
        POSTGRES.start();
        var datasource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(datasource).load().migrate();
        jdbc = new JdbcTemplate(datasource);
        execution = IacJobTestSupport.execution(jdbc, new IacJobProperties(true, Duration.ofSeconds(1),
                Duration.ofMinutes(5), 10, Duration.ofSeconds(30), Duration.ofMinutes(30), Duration.ofMinutes(5)),
                new DataSourceTransactionManager(datasource));
    }

    @AfterAll
    static void stop() {
        POSTGRES.stop();
    }

    @BeforeEach
    void reset() {
        jdbc.execute("TRUNCATE iac_findings, iac_jobs, iac_runs, iac_repos, iac_audit_events RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO iac_repos (full_name, default_branch, environment) VALUES ('Logssey/infrastructure', 'main', 'PROD')");
    }

    @Test
    void currentRepositoryHasOnlyNoiseDrift() {
        long run = check("nochange.json.gz");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_findings", Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT status || '/' || verdict FROM iac_runs WHERE run_id = ?", String.class, run))
                .isEqualTo("DONE/PASS");
        assertThat(jdbc.queryForObject("SELECT stats ->> 'noise' FROM iac_jobs WHERE run_id = ?", String.class, run)).isEqualTo("3");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_plan_payloads", Long.class)).isZero();
    }

    @Test
    void consoleDnsChangeIsAHighDriftUntilItIsReverted() {
        long run = check("drift-dns.json.gz");
        assertThat(jdbc.queryForObject("""
                SELECT rule_id || '|' || enforcement || '|' || severity || '|' || resource_address || '|' || (params ->> 'attributes')
                FROM iac_findings WHERE source = 'DRIFT' AND status = 'OPEN'
                """, String.class)).isEqualTo("drift.high|WARN|HIGH|module.edge.aws_route53_record.grafana[\"A\"]|[\"alias\"]");
        assertThat(jdbc.queryForObject("SELECT verdict || '/' || highest_severity FROM iac_runs WHERE run_id = ?",
                String.class, run)).isEqualTo("WARN/HIGH");

        check("drift-dns.json.gz");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_findings", Long.class)).as("같은 드리프트는 한 건").isEqualTo(1L);

        long fixedRun=check("nochange.json.gz");
        assertThat(jdbc.queryForObject("SELECT status FROM iac_findings", String.class)).isEqualTo("FIXED");
        assertThat(jdbc.queryForObject("SELECT j.run_id FROM iac_findings f JOIN iac_jobs j ON j.job_id=f.checked_job_id",Long.class)).isEqualTo(fixedRun);
        long again=check("nochange.json.gz");
        assertThat(jdbc.queryForObject("SELECT j.run_id FROM iac_findings f JOIN iac_jobs j ON j.job_id=f.checked_job_id",Long.class)).isEqualTo(again);
        assertThat(jdbc.queryForObject("SELECT stats->>'fixed' FROM iac_jobs WHERE run_id=?",String.class,again)).isEqualTo("0");
    }

    @Test
    void anotherRepositoryCannotCloseThisRepositorysDrift() {
        check("drift-dns.json.gz");
        jdbc.update("INSERT INTO iac_repos(full_name,default_branch,environment) VALUES('demo/other','main','DEV')");
        jdbc.update("UPDATE iac_runs SET repo_id=2");
        check("nochange.json.gz");
        assertThat(jdbc.queryForObject("SELECT status FROM iac_findings",String.class)).isEqualTo("OPEN");
    }

    private long check(String plan) {
        long run = jdbc.queryForObject("""
                INSERT INTO iac_runs (repo_id, head_sha, trigger_type, status) VALUES (1, repeat('a', 40), 'PUSH', 'ANALYZING')
                RETURNING run_id
                """, Long.class);
        byte[] gzip = resource("/plans/" + plan);
        jdbc.update("INSERT INTO iac_plan_payloads (run_id, content, size_bytes, expires_at) VALUES (?, ?, ?, now() + interval '1 hour')",
                run, gzip, gzip.length);
        jdbc.update("INSERT INTO iac_jobs (kind, trigger_type, run_id) VALUES ('CHECK_DRIFT', 'SCHEDULED', ?)", run);
        var claimed = execution.claimNextJob(IacJobKind.CHECK_DRIFT).orElseThrow();
        new CheckDriftProcessor(jdbc).process(claimed, execution);
        assertThat(execution.complete(claimed.jobId(), claimed.leaseToken())).isTrue();
        return run;
    }

    private static byte[] resource(String name) {
        try (var in = CheckDriftProcessorTest.class.getResourceAsStream(name)) {
            return in.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
