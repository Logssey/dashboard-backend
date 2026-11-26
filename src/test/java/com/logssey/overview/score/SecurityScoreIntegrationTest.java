package com.logssey.overview.score;

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
 * 보안 점수가 각 기능의 실제 테이블을 읽어 자산에 붙이는지 (IaC·코드·컴플라이언스, ADR-D012).
 * Secret은 admin에게 Secret 역할이 없어 NOT_AUTHORIZED, 이미지(Reach)는 결과가 없어 NO_DATA다
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
class SecurityScoreIntegrationTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final String RDS = "arn:aws:rds:ap-northeast-1:794386801311:db:reused";
    private static final String NODE_ROLE = "arn:aws:iam::794386801311:role/logssey-prod-role-node";

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
    private SecurityScoreService service;

    @Autowired
    private JdbcTemplate jdbc;

    @BeforeEach
    void reset() {
        jdbc.execute("TRUNCATE iac_attack_paths, iac_data_assets, iac_jobs, compliance_results, compliance_runs, "
                + "code_findings, code_scans RESTART IDENTITY CASCADE");
        // IaC: 방금 그래프를 모았고, 인터넷 → RDS 읽기 경로가 열려 있다
        jdbc.update("INSERT INTO iac_data_assets (arn, kind, tier) VALUES (?, 'RDS', 1)", RDS);
        jdbc.update("INSERT INTO iac_jobs (kind, trigger_type, status, finished_at) "
                + "VALUES ('COLLECT_GRAPH', 'SCHEDULED', 'SUCCEEDED', now() - interval '1 hour')");
        jdbc.update("""
                INSERT INTO iac_attack_paths (fingerprint, entry, target_data_asset_id, tier, severity, environment,
                                              hops, length, status, first_seen_at, last_seen_at)
                VALUES ('p1', 'internet', 1, 1, 'CRITICAL', 'PROD', '[]'::jsonb, 2, 'OPEN', now() - interval '1 day', now())
                """);
        // 코드: service-backend 워크플로 파일에 HIGH 하나 (배포 경로)
        long scan = jdbc.queryForObject("INSERT INTO code_scans (repository, tool, commit_sha, total) "
                + "VALUES ('Logssey/service-backend', 'semgrep', ?, 1) RETURNING scan_id", Long.class, "a".repeat(40));
        jdbc.update("INSERT INTO code_findings (scan_id, seq, rule_id, severity, message, path, line) "
                + "VALUES (?, 1, 'yaml.github-actions.run-shell-injection', 'HIGH', 'm', '.github/workflows/ci.yml', 240)", scan);
        // 컴플라이언스: 예전 점검의 FAIL은 세지 않는다. 최신 점검의 Node Role FAIL은 Node Role에, 계정 점검은 미분류로
        long old = run();
        result(old, "s3_public", "FAIL", "Critical", "arn:aws:s3:::old");
        long latest = run();
        result(latest, "iam_role_administratoraccess_policy", "FAIL", "High", NODE_ROLE);
        result(latest, "cloudtrail_multi_region_enabled", "FAIL", "Medium", "arn:aws:cloudtrail:ap-northeast-1:794386801311:trail");
        result(latest, "s3_bucket_default_encryption", "PASS", "High", "arn:aws:s3:::images");
    }

    @Test
    void readsEachPartAndPlacesFindingsOnAssets() {
        var r = service.score("admin");

        assertThat(asset(r, "rds").deduction()).isEqualTo(99);
        assertThat(asset(r, "deploy-path").deduction()).isEqualTo(73);
        assertThat(asset(r, "node-role").status()).isEqualTo("EVALUATED");
        assertThat(asset(r, "node-role").deduction()).isEqualTo(73);
        assertThat(asset(r, "unclassified-compliance").deduction()).isEqualTo(47);
        assertThat(asset(r, "web").status()).isEqualTo("NOT_EVALUATED");   // service-frontend 검사가 없다

        // 평가 범위 23 ÷ 24, 점수 100 − (3×99 + 3×73 + 3×73 + 3×47) ÷ 26
        assertThat(r.coverage()).isEqualTo(96);
        assertThat(r.score()).isEqualTo(66);
        assertThat(r.indicators().openCritical()).isEqualTo(1);
        assertThat(r.parts()).extracting(SecurityScoreResponse.Part::part, SecurityScoreResponse.Part::status)
                .contains(org.assertj.core.groups.Tuple.tuple("IAC", "CONNECTED"),
                        org.assertj.core.groups.Tuple.tuple("CODE", "CONNECTED"),
                        org.assertj.core.groups.Tuple.tuple("COMPLIANCE", "CONNECTED"),
                        org.assertj.core.groups.Tuple.tuple("SECRET", "NOT_AUTHORIZED"),
                        org.assertj.core.groups.Tuple.tuple("VULNERABILITY", "NO_DATA"));
    }

    private long run() {
        return jdbc.queryForObject("""
                INSERT INTO compliance_runs (target_key, environment, status, source, product, scanner_version, artifact_sha256,
                    input_count, result_count, duplicate_count, warning_count, pass_count, fail_count, error_count,
                    needs_review_count, created_by_login, finished_at)
                VALUES ('aws-main', 'prod', 'COMPLETED', 'IMPORT', 'prowler', '5', ?, 1, 1, 0, 0, 0, 1, 0, 0, 'admin',
                        now() - interval '1 day' + (SELECT count(*) FROM compliance_runs) * interval '1 hour')
                RETURNING run_id
                """, Long.class, String.format("%064x", System.nanoTime()));
    }

    private void result(long runId, String check, String result, String severity, String asset) {
        jdbc.update("""
                INSERT INTO compliance_results (run_id, check_id, title, provider, result, asset, current_value, expected_value,
                    observed_at, region, severity, fingerprint, asset_uid, asset_type)
                VALUES (?, ?, ?, 'aws', ?, ?, '-', '-', now(), 'ap-northeast-1', ?, ?, ?, 'resource')
                """, runId, check, "check " + check, result, asset, severity, check + "|" + asset, asset);
    }

    private static SecurityScoreResponse.AssetScore asset(SecurityScoreResponse r, String id) {
        return r.assets().stream().filter(a -> a.id().equals(id)).findFirst().orElseThrow();
    }
}
