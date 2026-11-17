package com.logssey.compliance;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;

import javax.sql.DataSource;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.mock.web.MockMultipartFile;
import org.testcontainers.containers.PostgreSQLContainer;

class ComplianceImportIntegrationTest {

    private static final PostgreSQLContainer<?> DATABASE = new PostgreSQLContainer<>("postgres:16-alpine");
    private static ComplianceService service;
    private static ComplianceReportService reports;
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
        var repository = new ComplianceRepository(JdbcClient.create(dataSource), jdbc);
        var catalog = new ComplianceCatalog();
        service = new ComplianceService(repository, catalog, new ProwlerOcsfNormalizer(),
                "reused", 8 * 1024 * 1024);
        reports = new ComplianceReportService(repository, catalog,
                new ComplianceTargetRepository(JdbcClient.create(dataSource)), "reused", "Re:Used");
    }

    @AfterAll
    static void stop() {
        DATABASE.stop();
    }

    @Test
    void importsNormalizesAssessesAndQueriesOneRun() {
        String payload = """
                [{
                  "metadata":{"event_code":"securityhub_enabled","product":{"name":"Prowler","version":"5.46.0"}},
                  "status_code":"FAIL",
                  "finding_info":{"uid":"aws:securityhub:123456789012","title":"Security Hub is disabled <script>alert(1)</script>"},
                  "cloud":{"provider":"aws"},
                  "resources":[{"uid":"123456789012","name":"123456789012","region":"ap-northeast-2"}],
                  "severity":"High",
                  "time_dt":"2026-11-16T01:00:00Z"
                }]
                """;
        var file = new MockMultipartFile("file", "prowler.json", "application/json",
                payload.getBytes(StandardCharsets.UTF_8));

        var imported = service.importProwler("admin", "reused", "prod", file);
        var overview = service.overview("reused", "PROD");
        var detail = service.run("reused", imported.runId());

        assertThat(imported.importedCount()).isEqualTo(1);
        assertThat(overview.latestRun()).isNotNull();
        assertThat(overview.latestRun().counts().fail()).isEqualTo(1);
        assertThat(overview.frameworks()).anyMatch(framework -> framework.technicalFail() > 0);
        assertThat(detail.results()).singleElement().satisfies(result -> {
            assertThat(result.checkId()).isEqualTo("securityhub_enabled");
            assertThat(result.asset()).isEqualTo("1234****9012");
        });
        assertThat(jdbc.queryForObject("SELECT length(artifact_sha256) FROM compliance_runs", Integer.class))
                .isEqualTo(64);

        String integrated = new String(reports.report("reused", imported.runId(), "all").content(), StandardCharsets.UTF_8);
        String iso = new String(reports.report("reused", imported.runId(), "iso").content(), StandardCharsets.UTF_8);
        assertThat(integrated).contains("통합 컴플라이언스", "Security Hub is disabled", "인증 적합 판정이 아닙니다", "&lt;script&gt;")
                .doesNotContain("123456789012", "<script>");
        assertThat(iso).contains("ISO/IEC 27001:2022").doesNotContain("ISMS-P 2023", "CSAP SaaS 표준등급");
    }
}
