package com.logssey.overview;

import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

import com.logssey.overview.dto.response.OverviewSummaryResponse;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * 통합 현황이 각 보안 기능의 실제 결과를 같은 원인끼리 묶어 세는지 (컴플라이언스·코드 취약점·런타임).
 * IaC·취약점 관리는 리포트 장을 그대로 쓰고, 이 테스트에서는 결과가 없다 (NO_DATA).
 */
@SpringBootTest(properties = {
        "spring.config.import=",
        "logssey.admin.login-id=admin",
        "logssey.admin.password=admin-pass",
        "logssey.admin.display-name=Security Admin",
        "logssey.secret.bootstrap-security-login-id=",
        "logssey.secret.bootstrap-operations-login-id=",
        "logssey.secret.bootstrap-remediator-login-id=",
        "logssey.secret.bootstrap-remediator-team="
})
class OverviewIntegrationTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");

    static {
        POSTGRES.start();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry properties) {
        properties.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        properties.add("spring.datasource.username", POSTGRES::getUsername);
        properties.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @Autowired
    private OverviewService overview;

    @Autowired
    private JdbcTemplate jdbc;

    @BeforeEach
    void reset() {
        jdbc.execute("TRUNCATE compliance_results, compliance_runs, code_findings, code_scans, runtime_findings RESTART IDENTITY CASCADE");
        // 컴플라이언스: 예전 점검의 FAIL 은 세지 않는다. 최신 점검에서 같은 항목 FAIL 두 자원은 한 건
        long old = run("prod");
        result(old, "s3_public", "FAIL", "critical", "arn:old");
        long prod = run("prod");
        result(prod, "iam_root_mfa", "FAIL", "critical", "arn:root");
        result(prod, "ec2_imdsv2", "FAIL", "high", "arn:i-1");
        result(prod, "ec2_imdsv2", "FAIL", "medium", "arn:i-2");
        result(prod, "s3_encryption", "PASS", "high", "arn:bucket");
        long dev = run("dev");
        result(dev, "ec2_imdsv2", "FAIL", "high", "arn:i-dev");
        // 코드: 같은 레포의 같은 규칙 여러 위치는 한 건
        long scan = jdbc.queryForObject("INSERT INTO code_scans (repository, tool, commit_sha, total) VALUES "
                + "('Logssey/service-backend', 'semgrep', ?, 3) RETURNING scan_id", Long.class, "a".repeat(40));
        code(scan, 0, "yaml.mutable-action-tag", "MEDIUM");
        code(scan, 1, "yaml.mutable-action-tag", "MEDIUM");
        code(scan, 2, "yaml.run-shell-injection", "HIGH");
        // 런타임: 같은 규칙 두 워크로드는 한 건. 해결·정상 동작은 빼고, 평가 전은 미평가
        runtime("r1", "shell_in_container", "OPEN", "UNDECIDED", "EVALUATED", "HIGH");
        runtime("r2", "shell_in_container", "IN_PROGRESS", "UNDECIDED", "EVALUATED", "MEDIUM");
        runtime("r3", "write_below_etc", "RESOLVED", "UNDECIDED", "EVALUATED", "CRITICAL");
        runtime("r4", "package_manager", "OPEN", "EXPECTED", "EVALUATED", "CRITICAL");
        runtime("r5", "unknown_binary", "OPEN", "UNDECIDED", "PENDING_CONTEXT", null);
    }

    @Test
    void eachPartIsCountedOncePerCauseAndTheScoreUsesThoseCounts() {
        var summary = overview.getSummary(EnvironmentFilter.ALL, "admin");
        Map<String, OverviewSummaryResponse.PartSummary> parts = summary.parts().stream()
                .collect(Collectors.toMap(OverviewSummaryResponse.PartSummary::part, Function.identity()));

        // 컴플라이언스 prod: root MFA(Critical) + IMDSv2(High, 두 자원) / dev: IMDSv2(High)
        assertThat(parts.get("COMPLIANCE")).satisfies(p -> {
            assertThat(p.status()).isEqualTo("CONNECTED");
            assertThat(p.critical()).isEqualTo(1);
            assertThat(p.high()).isEqualTo(2);
            assertThat(p.total()).isEqualTo(3);
            assertThat(p.penalty()).isEqualTo(6);
        });
        assertThat(parts.get("CODE")).satisfies(p -> {
            assertThat(p.high()).isEqualTo(1);
            assertThat(p.medium()).isEqualTo(1);
            assertThat(p.total()).isEqualTo(2);
        });
        assertThat(parts.get("RUNTIME")).satisfies(p -> {
            assertThat(p.high()).isEqualTo(1);
            assertThat(p.unassessed()).isEqualTo(1);
            assertThat(p.critical()).isZero();
            assertThat(p.total()).isEqualTo(2);
        });
        assertThat(parts.get("IAC").status()).isEqualTo("NO_DATA");
        assertThat(parts.get("SECRET").status()).isEqualTo("NOT_AUTHORIZED");
        assertThat(parts).doesNotContainKey("LEGACY");

        assertThat(summary.totalCount()).isEqualTo(7);
        assertThat(summary.unreviewedCriticalCount()).isEqualTo(1);
        assertThat(summary.securityScore()).isEqualTo(100 - 1 * 4 - 4);
        assertThat(summary.lastCollectedAt()).isNotNull();
    }

    @Test
    void aPartWithoutResultsIsShownAsNoDataNotAsAnError() {
        jdbc.execute("TRUNCATE compliance_results, compliance_runs, code_findings, code_scans, runtime_findings RESTART IDENTITY CASCADE");
        var summary = overview.getSummary(EnvironmentFilter.ALL, "admin");
        assertThat(summary.parts()).filteredOn(p -> !"SECRET".equals(p.part()))
                .allSatisfy(p -> assertThat(p.status()).isEqualTo("NO_DATA"));
        assertThat(summary.securityScore()).isEqualTo(100);
        assertThat(summary.totalCount()).isZero();
    }

    @Test
    void theEnvironmentFilterKeepsDevOnlyForPartsThatKnowIt() {
        var dev = overview.getSummary(EnvironmentFilter.DEV, "admin");
        assertThat(dev.totalCount()).isEqualTo(1);
        assertThat(dev.securityScore()).isEqualTo(99);
        var prod = overview.getSummary(EnvironmentFilter.PROD, "admin");
        assertThat(prod.totalCount()).isEqualTo(6);

        assertThat(overview.getAssetSummary(EnvironmentFilter.ALL).providers())
                .anySatisfy(p -> { assertThat(p.provider()).isEqualTo("AWS"); assertThat(p.count()).isEqualTo(5); })
                .anySatisfy(p -> { assertThat(p.provider()).isEqualTo("GITHUB"); assertThat(p.count()).isEqualTo(1); });
        assertThat(overview.getAssetSummary(EnvironmentFilter.DEV).providers())
                .anySatisfy(p -> { assertThat(p.provider()).isEqualTo("AWS"); assertThat(p.count()).isEqualTo(1); })
                .anySatisfy(p -> { assertThat(p.provider()).isEqualTo("GITHUB"); assertThat(p.count()).isZero(); });
    }

    @Test
    void thePriorityListMixesPartsBySeverityAndLinksToEachPart() {
        var priority = overview.getPriorityFindings(EnvironmentFilter.ALL, 4, "admin");
        assertThat(priority.unreviewedCount()).isEqualTo(7);
        assertThat(priority.items()).hasSize(4);
        var first = priority.items().getFirst();
        assertThat(first.severity()).isEqualTo("CRITICAL");
        assertThat(first.sourceType()).isEqualTo("PART_FINDING");
        assertThat(first.displayId()).isEqualTo("컴플라이언스");
        assertThat(first.detailPath()).isEqualTo("/configuration");
        assertThat(priority.items()).extracting(p -> p.severity()).containsExactly("CRITICAL", "HIGH", "HIGH", "HIGH");
        assertThat(priority.items()).anySatisfy(p -> {
            assertThat(p.detailPath()).isEqualTo("/configuration");
            assertThat(p.evidence()).isEqualTo("같은 원인 2건을 한 건으로 묶었어요.");
        });

        var trend = overview.getRiskTrend(EnvironmentFilter.ALL, 1, "admin").days().getFirst();
        assertThat(trend.total()).isEqualTo(7);
        assertThat(trend.critical()).isEqualTo(1);
    }

    private long run(String environment) {
        return jdbc.queryForObject("""
                INSERT INTO compliance_runs (target_key, environment, status, source, product, scanner_version, artifact_sha256,
                    input_count, result_count, duplicate_count, warning_count, pass_count, fail_count, error_count,
                    needs_review_count, created_by_login)
                VALUES ('aws-main', ?, 'COMPLETED', 'IMPORT', 'prowler', '5', ?, 1, 1, 0, 0, 0, 1, 0, 0, 'admin')
                RETURNING run_id
                """, Long.class, environment, String.format("%064x", System.nanoTime()));
    }

    private void result(long runId, String check, String result, String severity, String asset) {
        jdbc.update("""
                INSERT INTO compliance_results (run_id, check_id, title, provider, result, asset, current_value, expected_value,
                    observed_at, region, severity, fingerprint, asset_uid, asset_type)
                VALUES (?, ?, ?, 'aws', ?, ?, '-', '-', now(), 'ap-northeast-1', ?, ?, ?, 'resource')
                """, runId, check, "check " + check, result, asset, severity, runId + check + asset, asset);
    }

    private void code(long scanId, int seq, String rule, String severity) {
        jdbc.update("INSERT INTO code_findings (scan_id, seq, rule_id, severity, message, path, line) VALUES (?, ?, ?, ?, 'm', 'a.yml', 1)",
                scanId, seq, rule, severity);
    }

    private void runtime(String id, String rule, String action, String disposition, String evaluation, String severity) {
        jdbc.update("""
                INSERT INTO runtime_findings (fingerprint, rule_key, rule_title, rule_version, source_priority,
                    final_severity, evaluation_status, action_status, disposition, first_seen_at, last_seen_at,
                    target_type, target_name, operation)
                VALUES (?, ?, ?, '1', 'WARNING', ?, ?, ?, ?, now(), now(), 'PROCESS', 'sh', 'exec')
                """, "fp-" + id, rule, "rule " + rule, severity, evaluation, action, disposition);
    }
}
