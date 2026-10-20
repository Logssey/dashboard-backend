package com.logssey.iac;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** ERD "구현 검증": 기존 V10 위에 IaC 마이그레이션(V11~) 적용, 잘못된 FK·값 거부, 같은 지문 중복 거부. */
class IacSchemaMigrationTest {
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final String SHA = "a".repeat(40);
    private static JdbcTemplate jdbc;

    @BeforeAll
    static void database() {
        POSTGRES.start();
        var datasource = new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        // 이미 V10 까지 적용된 DB 에 V11 을 올리는 순서로 확인한다.
        Flyway.configure().dataSource(datasource).target("10").load().migrate();
        Flyway.configure().dataSource(datasource).load().migrate();
        jdbc = new JdbcTemplate(datasource);
    }

    @AfterAll
    static void close() {
        POSTGRES.stop();
    }

    @Test
    void appliesOnTopOfExistingSchemaAndSeedsRules() {
        assertThat(jdbc.queryForObject(
                "SELECT COUNT(*) FROM flyway_schema_history WHERE success AND version IN ('11','12')",
                Integer.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_rules", Integer.class)).isEqualTo(23);
        assertThat(jdbc.queryForObject(
                "SELECT count(*) FROM iac_rules WHERE rule_id LIKE 'gate.%'", Integer.class)).isEqualTo(13);
        assertThat(jdbc.queryForObject(
                "SELECT default_enforcement || '/' || default_severity FROM iac_rules WHERE rule_id = 'path.tier1.added'",
                String.class)).isEqualTo("BLOCK/CRITICAL");
    }

    @Test
    void rejectsUnknownForeignKeys() {
        assertThatThrownBy(() -> jdbc.update("""
                INSERT INTO iac_runs (repo_id, pr_number, head_sha, trigger_type, status)
                VALUES (999999, 1, ?, 'PR', 'QUEUED')
                """, SHA)).isInstanceOf(DataIntegrityViolationException.class);

        long run = run();
        assertThatThrownBy(() -> jdbc.update("""
                INSERT INTO iac_findings (rule_id, source, enforcement, environment, fingerprint, last_run_id,
                                          first_seen_at, last_seen_at)
                VALUES ('gate.unknown', 'GATE', 'BLOCK', 'PROD', 'fp-unknown-rule', ?, now(), now())
                """, run)).isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void rejectsValuesOutsideTheEnumsAndRowRules() {
        long repo = repo();
        assertThatThrownBy(() -> jdbc.update("""
                INSERT INTO iac_runs (repo_id, pr_number, head_sha, trigger_type, status)
                VALUES (?, 1, ?, 'PR', 'BOGUS')
                """, repo, SHA)).isInstanceOf(DataIntegrityViolationException.class);
        // PR 실행인데 PR 번호가 없음
        assertThatThrownBy(() -> jdbc.update("""
                INSERT INTO iac_runs (repo_id, head_sha, trigger_type, status) VALUES (?, ?, 'PR', 'QUEUED')
                """, repo, SHA)).isInstanceOf(DataIntegrityViolationException.class);
        // ANALYZE_RUN 작업인데 실행이 없음
        assertThatThrownBy(() -> jdbc.update(
                "INSERT INTO iac_jobs (kind, trigger_type) VALUES ('ANALYZE_RUN', 'PR')"))
                .isInstanceOf(DataIntegrityViolationException.class);
        // 사용자 감사 행인데 사용자가 없음
        assertThatThrownBy(() -> jdbc.update("""
                INSERT INTO iac_audit_events (actor_kind, entity_type, entity_id, event_type)
                VALUES ('USER', 'RUN', 1, 'RERUN')
                """)).isInstanceOf(DataIntegrityViolationException.class);
        // 발견 건은 실행이나 작업 중 하나에서 나와야 함
        assertThatThrownBy(() -> jdbc.update("""
                INSERT INTO iac_findings (rule_id, source, enforcement, environment, fingerprint,
                                          first_seen_at, last_seen_at)
                VALUES ('gate.provisioner', 'GATE', 'BLOCK', 'PROD', 'fp-no-origin', now(), now())
                """)).isInstanceOf(DataIntegrityViolationException.class);
        // 20MB 를 넘는 plan
        long run = run();
        assertThatThrownBy(() -> jdbc.update("""
                INSERT INTO iac_plan_payloads (run_id, content, size_bytes, expires_at)
                VALUES (?, '\\x00', 20971521, now() + interval '1 hour')
                """, run)).isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void rejectsDuplicateFingerprints() {
        long run = run();
        String finding = """
                INSERT INTO iac_findings (rule_id, source, enforcement, environment, fingerprint, last_run_id,
                                          first_seen_at, last_seen_at)
                VALUES ('gate.provisioner', 'GATE', 'BLOCK', 'PROD', 'fp-dup', ?, now(), now())
                """;
        jdbc.update(finding, run);
        assertThatThrownBy(() -> jdbc.update(finding, run)).isInstanceOf(DataIntegrityViolationException.class);

        long asset = jdbc.queryForObject("""
                INSERT INTO iac_data_assets (arn, kind, tier) VALUES ('arn:aws:s3:::dup-test', 'S3', 1)
                RETURNING data_asset_id
                """, Long.class);
        String path = """
                INSERT INTO iac_attack_paths (fingerprint, entry, target_data_asset_id, tier, severity, environment,
                                              hops, length, first_seen_at, last_seen_at)
                VALUES ('path-dup', 'internet', ?, 1, 'CRITICAL', 'PROD', '[]', 0, now(), now())
                """;
        jdbc.update(path, asset);
        assertThatThrownBy(() -> jdbc.update(path, asset)).isInstanceOf(DataIntegrityViolationException.class);

        String change = """
                INSERT INTO iac_run_path_changes (run_id, change, rule_id, path_fingerprint, tier, hops)
                VALUES (?, 'ADDED', 'path.tier1.added', 'change-dup', 1, '[]')
                """;
        jdbc.update(change, run);
        assertThatThrownBy(() -> jdbc.update(change, run)).isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void addedPathChangeCannotPointAtAnExistingPath() {
        long run = run();
        long asset = jdbc.queryForObject("""
                INSERT INTO iac_data_assets (arn, kind, tier) VALUES ('arn:aws:s3:::added-test', 'S3', 1)
                RETURNING data_asset_id
                """, Long.class);
        long path = jdbc.queryForObject("""
                INSERT INTO iac_attack_paths (fingerprint, entry, target_data_asset_id, tier, severity, environment,
                                              hops, length, first_seen_at, last_seen_at)
                VALUES ('path-existing', 'internet', ?, 1, 'CRITICAL', 'PROD', '[]', 0, now(), now())
                RETURNING path_id
                """, Long.class, asset);
        assertThatThrownBy(() -> jdbc.update("""
                INSERT INTO iac_run_path_changes (run_id, change, rule_id, path_id, path_fingerprint, tier, hops)
                VALUES (?, 'ADDED', 'path.tier1.added', ?, 'path-existing', 1, '[]')
                """, run, path)).isInstanceOf(DataIntegrityViolationException.class);
    }

    @Test
    void deletingARunRemovesItsPlanAndPathChanges() {
        long run = run();
        jdbc.update("""
                INSERT INTO iac_plan_payloads (run_id, content, size_bytes, expires_at)
                VALUES (?, '\\x00', 1, now() + interval '1 hour')
                """, run);
        jdbc.update("""
                INSERT INTO iac_run_path_changes (run_id, change, rule_id, path_fingerprint, tier, hops)
                VALUES (?, 'REMOVED', 'path.removed', 'cascade', 1, '[]')
                """, run);
        jdbc.update("DELETE FROM iac_runs WHERE run_id = ?", run);
        assertThat(jdbc.queryForObject(
                "SELECT count(*) FROM iac_plan_payloads WHERE run_id = ?", Integer.class, run)).isZero();
        assertThat(jdbc.queryForObject(
                "SELECT count(*) FROM iac_run_path_changes WHERE run_id = ?", Integer.class, run)).isZero();
    }

    private static long repo() {
        return jdbc.queryForObject("""
                INSERT INTO iac_repos (full_name, default_branch, environment)
                VALUES ('test/repo-' || gen_random_uuid(), 'main', 'PROD')
                RETURNING repo_id
                """, Long.class);
    }

    private static long run() {
        return jdbc.queryForObject("""
                INSERT INTO iac_runs (repo_id, pr_number, head_sha, trigger_type, status)
                VALUES (?, 1, ?, 'PR', 'QUEUED')
                RETURNING run_id
                """, Long.class, repo(), SHA);
    }
}
