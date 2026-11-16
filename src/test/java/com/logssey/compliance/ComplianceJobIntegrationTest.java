package com.logssey.compliance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;

import javax.sql.DataSource;

import com.logssey.common.error.ApiException;
import com.logssey.compliance.ComplianceJobDtos.CreateJobRequest;
import com.logssey.compliance.ComplianceJobDtos.LeaseRequest;
import com.logssey.compliance.ComplianceJobDtos.ScanScope;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.mock.web.MockMultipartFile;
import org.testcontainers.containers.PostgreSQLContainer;

class ComplianceJobIntegrationTest {

    private static final PostgreSQLContainer<?> DATABASE = new PostgreSQLContainer<>("postgres:16-alpine");
    private static ComplianceJobService jobs;
    private static ComplianceJobService disabledJobs;
    private static JdbcTemplate jdbc;

    @BeforeAll
    static void start() {
        DATABASE.start();
        DataSource dataSource = new DriverManagerDataSource(
                DATABASE.getJdbcUrl(), DATABASE.getUsername(), DATABASE.getPassword());
        Flyway.configure().dataSource(dataSource).load().migrate();
        jdbc = new JdbcTemplate(dataSource);
        jdbc.update("""
                INSERT INTO dashboard_users (login_id, password_hash, display_name, role)
                VALUES ('admin', 'unused', 'Admin', 'ADMIN')
                """);
        var complianceRepository = new ComplianceRepository(JdbcClient.create(dataSource), jdbc);
        var compliance = new ComplianceService(complianceRepository, new ComplianceCatalog(),
                new ProwlerOcsfNormalizer(), "reused", 8 * 1024 * 1024);
        jobs = new ComplianceJobService(new ComplianceJobRepository(JdbcClient.create(dataSource)),
                complianceRepository, compliance, new ProwlerScopeCatalog(), "reused", 300, 1, true);
        disabledJobs = new ComplianceJobService(new ComplianceJobRepository(JdbcClient.create(dataSource)),
                complianceRepository, compliance, new ProwlerScopeCatalog(), "reused", 300, 1, false);
    }

    @AfterAll
    static void stop() {
        DATABASE.stop();
    }

    @Test
    void createsClaimsHeartbeatsAndCompletesAValidatedJob() {
        var created = jobs.create("admin", new CreateJobRequest("prod",
                new ScanScope(java.util.List.of("ap-northeast-2"), java.util.List.of("s3"), java.util.List.of())));
        var claimed = jobs.claim("worker-1");

        assertThat(claimed.jobId()).isEqualTo(created.jobId());
        assertThat(claimed.scope().services()).containsExactly("s3");
        assertThat(jobs.heartbeat(claimed.jobId(),
                new LeaseRequest(claimed.leaseToken(), claimed.leaseGeneration())).leaseUntil())
                .isAfter(claimed.leaseUntil());

        String payload = """
                [{
                  "metadata":{"event_code":"s3_bucket_public_access_block","product":{"name":"Prowler","version":"5.46.0"}},
                  "status_code":"PASS",
                  "finding_info":{"uid":"aws:s3:example","title":"S3 public access block"},
                  "cloud":{"provider":"aws"},
                  "resources":[{"uid":"arn:aws:s3:::example","name":"example","region":"ap-northeast-2"}],
                  "severity":"Informational",
                  "time_dt":"2026-11-16T01:00:00Z"
                }]
                """;
        var file = new MockMultipartFile("file", "result.ocsf.json", "application/json",
                payload.getBytes(StandardCharsets.UTF_8));
        var completed = jobs.complete(claimed.jobId(), claimed.leaseToken(), claimed.leaseGeneration(), file);

        assertThat(completed.status()).isEqualTo("SUCCEEDED");
        assertThat(jobs.job(claimed.jobId()).runId()).isEqualTo(completed.runId());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM compliance_runs", Long.class)).isEqualTo(1);
        assertThatThrownBy(() -> jobs.heartbeat(claimed.jobId(),
                new LeaseRequest(claimed.leaseToken(), claimed.leaseGeneration())))
                .isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> jobs.complete(claimed.jobId(), claimed.leaseToken(),
                claimed.leaseGeneration(), file)).isInstanceOf(ApiException.class);
    }

    @Test
    void rejectsUnknownChecksAndMutuallyExclusiveSelectors() {
        assertThatThrownBy(() -> jobs.create("admin", new CreateJobRequest("dev",
                new ScanScope(java.util.List.of(), java.util.List.of(), java.util.List.of("not_a_real_check")))))
                .isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> jobs.create("admin", new CreateJobRequest("dev",
                new ScanScope(java.util.List.of(), java.util.List.of("s3"),
                        java.util.List.of("s3_bucket_public_access_block")))))
                .isInstanceOf(ApiException.class);
    }

    @Test
    void disabledExecutionIsVisibleAndRejectsNewJobs() {
        assertThat(disabledJobs.scopeCatalog().executionEnabled()).isFalse();
        assertThatThrownBy(() -> disabledJobs.create("admin", new CreateJobRequest("prod",
                new ScanScope(java.util.List.of(), java.util.List.of(), java.util.List.of()))))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("운영 연결");
    }

    @Test
    void cancellationFencesTheClaimedWorkerAndTerminalJobsCannotBeCancelled() {
        var created = jobs.create("admin", new CreateJobRequest("dev",
                new ScanScope(java.util.List.of(), java.util.List.of(), java.util.List.of())));
        var claimed = jobs.claim("worker-cancel");

        assertThat(jobs.cancel("admin", created.jobId()).status()).isEqualTo("CANCELLED");
        assertThat(jobs.job(created.jobId()).status()).isEqualTo("CANCELLED");
        assertThatThrownBy(() -> jobs.heartbeat(claimed.jobId(),
                new LeaseRequest(claimed.leaseToken(), claimed.leaseGeneration())))
                .isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> jobs.cancel("admin", created.jobId()))
                .isInstanceOf(ApiException.class);
    }

    @Test
    void expiredLeaseIsReclaimedWithANewTokenAndGeneration() {
        var created = jobs.create("admin", new CreateJobRequest("prod",
                new ScanScope(java.util.List.of(), java.util.List.of("iam"), java.util.List.of())));
        var first = jobs.claim("worker-old");
        jdbc.update("UPDATE compliance_scan_jobs SET lease_until = clock_timestamp() - interval '1 second' "
                + "WHERE job_id = ?", created.jobId());

        var second = jobs.claim("worker-new");

        assertThat(second.jobId()).isEqualTo(first.jobId());
        assertThat(second.leaseGeneration()).isEqualTo(first.leaseGeneration() + 1);
        assertThat(second.leaseToken()).isNotEqualTo(first.leaseToken());
        assertThatThrownBy(() -> jobs.heartbeat(first.jobId(),
                new LeaseRequest(first.leaseToken(), first.leaseGeneration())))
                .isInstanceOf(ApiException.class);
        jobs.cancel("admin", second.jobId());
    }
}
