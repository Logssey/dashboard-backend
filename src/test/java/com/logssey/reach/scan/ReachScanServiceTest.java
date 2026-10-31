package com.logssey.reach.scan;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.scan.dto.ReachScanResponse;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.entry;

class ReachScanServiceTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static JdbcTemplate jdbc;
    private ReachScanService service;

    @BeforeAll
    static void startDatabase() {
        POSTGRES.start();
        var datasource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(datasource).load().migrate();   // 버전 번호를 적지 않는다
        jdbc = new JdbcTemplate(datasource);
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @BeforeEach
    void reset() {
        jdbc.execute("TRUNCATE reach_review_history, reach_reviews, reach_evidence, reach_verdicts, "
                + "reach_findings, reach_scans, reach_targets, dashboard_users RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO dashboard_users (login_id, password_hash, display_name, role) "
                + "VALUES ('admin', 'h', 'Admin', 'ADMIN')");
        service = new ReachScanService(new ReachScanRepository(JdbcClient.create(jdbc)));
    }

    @Test
    void requiresAdmin() {
        long id = scan(target("sha256:a"), "SUCCEEDED");
        assertError(() -> service.scan(null, id), ErrorCode.UNAUTHENTICATED);
        assertError(() -> service.scan("nobody", id), ErrorCode.FORBIDDEN);
    }

    @Test
    void succeededScanCountsItsToolVerdictsAndFillsZeros() {
        long target = target("sha256:a");
        long id = scan(target, "SUCCEEDED");
        finding(id, "a", "CRITICAL", "REACHABLE", "UNREVIEWED");
        finding(id, "b", "HIGH", "UNREACHABLE", "CONFIRMED");
        finding(id, "c", "HIGH", "NOT_ANALYZED", "UNREVIEWED");

        var scan = service.scan("admin", id);
        var counts = scan.counts();
        assertThat(counts.total()).isEqualTo(3);
        assertThat(counts.bySeverity()).containsExactly(entry("CRITICAL", 1L), entry("HIGH", 2L),
                entry("MEDIUM", 0L), entry("LOW", 0L), entry("UNKNOWN", 0L));
        assertThat(counts.byStatus()).containsExactly(entry("REACHABLE", 1L), entry("UNKNOWN", 0L),
                entry("UNREACHABLE", 1L), entry("NOT_ANALYZED", 1L));
        assertThat(counts.byReviewState()).containsExactly(entry("UNREVIEWED", 2L), entry("PROVISIONAL", 0L),
                entry("CONFIRMED", 1L));
        assertThat(scan.target().image().digest()).isEqualTo("sha256:a");
        assertThat(scan.target().repo()).isNull();
        assertThat(scan.failure()).isNull();

        // 판정이 0건이어도 counts는 null이 아니라 0
        var empty = service.scan("admin", scan(target, "SUCCEEDED")).counts();
        assertThat(empty.total()).isZero();
        assertThat(empty.byStatus()).containsEntry("REACHABLE", 0L);
    }

    @Test
    void runningScanHasNoCountsYet() {
        long id = scan(repoTarget("bb4639b"), "RUNNING");
        finding(id, "a", "HIGH", "UNREACHABLE", "UNREVIEWED");

        var scan = service.scan("admin", id);
        assertThat(scan.counts()).isNull();
        assertThat(scan.startedAt()).isNotNull();
        assertThat(scan.finishedAt()).isNull();
        assertThat(scan.target().repo().commit()).isEqualTo("bb4639b");
        assertThat(scan.target().image()).isNull();
    }

    @Test
    void failedScanHasFailureAndNoCounts() {
        long id = scan(target("sha256:a"), "FAILED");

        var scan = service.scan("admin", id);
        assertThat(scan.failure()).isEqualTo(new ReachScanResponse.Failure("E-L2-01", "L2", "call graph timed out"));
        assertThat(scan.counts()).isNull();
    }

    @Test
    void manualVerdictDoesNotChangeTheScanCounts() {
        long id = scan(target("sha256:a"), "SUCCEEDED");
        long finding = finding(id, "a", "HIGH", "NOT_ANALYZED", "UNREVIEWED");
        // 사람 판정이 현재 판정이 된 경우 (API-06 예외): 도구 판정을 끄고 MANUAL을 켠다
        jdbc.update("UPDATE reach_verdicts SET is_current = false WHERE finding_id = ?", finding);
        jdbc.update("""
                INSERT INTO reach_verdicts (finding_id, scan_id, status, method, summary, is_current, analyzed_at,
                                            created_by_user_id)
                VALUES (?, ?, 'UNREACHABLE', 'MANUAL', 'manual', true, now(), 1)
                """, finding, id);

        var counts = service.scan("admin", id).counts();
        assertThat(counts.total()).isEqualTo(1);
        assertThat(counts.byStatus()).containsEntry("NOT_ANALYZED", 1L).containsEntry("UNREACHABLE", 0L);
    }

    @Test
    void olderScanKeepsItsCountsAfterTheFindingAppearsAgain() {
        long target = target("sha256:a");
        long older = scan(target, "SUCCEEDED");
        long finding = finding(older, "a", "HIGH", "UNREACHABLE", "UNREVIEWED");
        // 다음 스캔에 같은 Finding이 다시 나와 판정이 바뀌고 last_scan_id가 새 스캔으로 옮겨진다
        long newer = scan(target, "SUCCEEDED");
        jdbc.update("UPDATE reach_verdicts SET is_current = false WHERE finding_id = ?", finding);
        verdict(finding, newer, "REACHABLE");
        jdbc.update("UPDATE reach_findings SET last_scan_id = ? WHERE finding_id = ?", newer, finding);

        assertThat(service.scan("admin", older).counts().byStatus())
                .containsEntry("UNREACHABLE", 1L).containsEntry("REACHABLE", 0L);
        assertThat(service.scan("admin", newer).counts().byStatus())
                .containsEntry("REACHABLE", 1L).containsEntry("UNREACHABLE", 0L);
    }

    @Test
    void returnsStagesAndToolsAsStored() {
        long id = scan(target("sha256:a"), "SUCCEEDED");
        jdbc.update("""
                UPDATE reach_scans
                SET stages = '[{"name": "L2", "status": "SUCCEEDED", "durationSeconds": 40}]',
                    tools = '{"trivy": "0.75.0", "reach": "v0"}'
                WHERE scan_id = ?
                """, id);

        var scan = service.scan("admin", id);
        assertThat(scan.stages().get(0).get("durationSeconds").asInt()).isEqualTo(40);
        assertThat(scan.tools().get("trivy").asString()).isEqualTo("0.75.0");
        assertThat(scan.analysis()).isNull();
    }

    @Test
    void requestedByShowsWhoAskedForTheScan() {
        long target = target("sha256:a");
        long system = scan(target, "SUCCEEDED");
        long user = scan(target, "QUEUED");
        jdbc.update("UPDATE reach_scans SET requested_by_kind = 'USER', requested_by_user_id = 1 WHERE scan_id = ?", user);

        assertThat(service.scan("admin", system).requestedBy())
                .isEqualTo(new ReachScanResponse.RequestedBy("SYSTEM", null, null, null));
        assertThat(service.scan("admin", user).requestedBy())
                .isEqualTo(new ReachScanResponse.RequestedBy("USER", 1L, null, null));
    }

    @Test
    void unknownScanIsNotFound() {
        assertError(() -> service.scan("admin", 999), ErrorCode.NOT_FOUND);
    }

    private static void assertError(org.assertj.core.api.ThrowableAssert.ThrowingCallable call, ErrorCode code) {
        assertThatThrownBy(call).satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(code));
    }

    private static long target(String digest) {
        return jdbc.queryForObject("""
                INSERT INTO reach_targets (target_type, app, image_repository, image_digest, display_name)
                VALUES ('IMAGE', 'API', 'reused-api', ?, 'api') RETURNING target_id
                """, Long.class, digest);
    }

    private static long repoTarget(String commit) {
        return jdbc.queryForObject("""
                INSERT INTO reach_targets (target_type, app, repo_name, repo_commit, display_name)
                VALUES ('REPO', 'API', 'service-backend', ?, 'api') RETURNING target_id
                """, Long.class, commit);
    }

    /** 상태에 맞게 시각과 실패 사유를 채운다 (V34 CHECK: 끝난 스캔만 finished_at, FAILED는 failure_code) */
    private static long scan(long targetId, String status) {
        boolean failed = status.equals("FAILED");
        return jdbc.queryForObject("""
                INSERT INTO reach_scans (target_id, scan_status, trigger_type, requested_by_kind, started_at, finished_at,
                                         failure_code, failure_stage, failure_message)
                VALUES (?, ?, 'MANUAL', 'SYSTEM',
                        CASE WHEN ? <> 'QUEUED' THEN now() END,
                        CASE WHEN ? IN ('SUCCEEDED', 'FAILED') THEN now() END,
                        ?, ?, ?)
                RETURNING scan_id
                """, Long.class, targetId, status, status, status,
                failed ? "E-L2-01" : null, failed ? "L2" : null, failed ? "call graph timed out" : null);
    }

    /** Finding + 그 스캔의 현재 판정 + 검토 한 벌. 검토 상태가 UNREVIEWED가 아니면 admin이 같은 판정으로 검토 */
    private static long finding(long scanId, String component, String severity, String status, String reviewState) {
        long id = jdbc.queryForObject("""
                INSERT INTO reach_findings (target_id, purl, component_name, component_version, ecosystem,
                                            vulnerability_id, severity, sources, last_scan_id, first_seen_at, last_seen_at)
                SELECT target_id, 'pkg:maven/test/' || ? || '@1', ?, '1', 'maven', 'CVE-2026-1', ?, ARRAY['TRIVY'],
                       scan_id, now(), now()
                FROM reach_scans WHERE scan_id = ? RETURNING finding_id
                """, Long.class, component, component, severity, scanId);
        verdict(id, scanId, status);
        boolean human = !reviewState.equals("UNREVIEWED");
        jdbc.update("""
                INSERT INTO reach_reviews (finding_id, review_state, status, note, reviewer_user_id, reviewed_at)
                VALUES (?, ?, ?, ?, ?, CASE WHEN ? THEN now() END)
                """, id, reviewState, human ? status : null, human ? "checked" : null, human ? 1L : null, human);
        return id;
    }

    /** 도구 판정을 현재 판정으로 넣는다. NOT_ANALYZED면 방식 없이 사유 OS_PACKAGE */
    private static void verdict(long findingId, long scanId, String status) {
        boolean notAnalyzed = status.equals("NOT_ANALYZED");
        jdbc.update("""
                INSERT INTO reach_verdicts (finding_id, scan_id, status, method, not_analyzed_reason, summary,
                                            engine, evidence_hash, is_current, analyzed_at)
                VALUES (?, ?, ?, ?, ?, 'test', '{}', 'h', true, now())
                """, findingId, scanId, status, notAnalyzed ? null : "CALLGRAPH", notAnalyzed ? "OS_PACKAGE" : null);
    }
}
