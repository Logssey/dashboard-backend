package com.logssey.reach.export;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.export.dto.ReachOcsfFindingResponse;
import com.logssey.reach.export.dto.ReachOcsfPageResponse;

import java.time.OffsetDateTime;
import java.util.List;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReachExportServiceTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final String DIGEST = "sha256:" + "a6ffffef".repeat(8);
    private static final String COMMIT = "6583020" + "0".repeat(33);
    private static JdbcTemplate jdbc;
    private ReachExportService service;

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
        service = new ReachExportService(new ReachExportRepository(JdbcClient.create(jdbc)));
    }

    @Test
    void requiresAdminAndScanId() {
        long id = scan(imageTarget(), "SUCCEEDED");
        assertError(() -> service.ocsf(null, id, null, null, null), ErrorCode.UNAUTHENTICATED);
        assertError(() -> service.ocsf("nobody", id, null, null, null), ErrorCode.FORBIDDEN);
        assertError(() -> service.ocsf("admin", null, null, null, null), ErrorCode.INVALID_INPUT);
    }

    @Test
    void unknownScanIsNotFoundAndUnfinishedScanIsConflict() {
        long target = imageTarget();
        long running = scan(target, "RUNNING");
        long failed = scan(target, "FAILED");
        assertError(() -> service.ocsf("admin", 999L, null, null, null), ErrorCode.NOT_FOUND);
        // 명세의 SCAN_NOT_READY(409) 대신 같은 409인 CONFLICT
        assertError(() -> service.ocsf("admin", running, null, null, null), ErrorCode.CONFLICT);
        assertError(() -> service.ocsf("admin", failed, null, null, null), ErrorCode.CONFLICT);
    }

    @Test
    void itemFollowsTheProposedOcsfShape() {
        long id = scan(imageTarget(), "SUCCEEDED");
        long finding = finding(id, "tomcat-embed-core", "11.0.24", "CVE-2026-68525", "CRITICAL", "UNREACHABLE",
                "CONFIRMED");
        jdbc.update("UPDATE reach_verdicts SET method = 'RULE', summary = 'FORM 인증(LoginConfig) 설정 없음' "
                + "WHERE finding_id = ?", finding);
        long os = finding(id, "zlib", "1.3.2-r0", "CVE-2026-85091", "MEDIUM", "NOT_ANALYZED", "UNREVIEWED");

        var items = list(id).items();
        assertThat(items).hasSize(2);
        var item = items.get(0);
        assertThat(item.className()).isEqualTo("Vulnerability Finding");
        assertThat(item.metadata().product()).isEqualTo(new ReachOcsfFindingResponse.Product("Reach", "Logssey"));
        assertThat(item.time()).isAtSameInstantAs(
                jdbc.queryForObject("SELECT finished_at FROM reach_scans WHERE scan_id = ?", OffsetDateTime.class, id));
        assertThat(item.findingInfo()).isEqualTo(new ReachOcsfFindingResponse.FindingInfo(
                String.valueOf(finding), "CVE-2026-68525 tomcat-embed-core 11.0.24"));
        var vulnerability = item.vulnerabilities().get(0);
        assertThat(vulnerability.cve().uid()).isEqualTo("CVE-2026-68525");
        assertThat(vulnerability.affectedPackages()).containsExactly(new ReachOcsfFindingResponse.AffectedPackage(
                "tomcat-embed-core", "11.0.24", "pkg:maven/org.example/tomcat-embed-core@11.0.24"));
        assertThat(item.resources()).containsExactly(new ReachOcsfFindingResponse.Resource("logssey/reused-api@" + DIGEST));
        assertThat(item.unmapped().reach()).isEqualTo(new ReachOcsfFindingResponse.Reach("CRITICAL", "UNREACHABLE",
                "RULE", "FORM 인증(LoginConfig) 설정 없음", "CONFIRMED", "RUNNING", "/api/v1/reach/findings/" + finding));

        // NOT_ANALYZED는 방식이 없어 null (명세 2-1)
        assertThat(items.get(1).findingInfo().uid()).isEqualTo(String.valueOf(os));
        assertThat(items.get(1).unmapped().reach().method()).isNull();

        // OCSF 이름은 snake_case로 나간다
        String json = JsonMapper.builder().build().writeValueAsString(item);
        assertThat(json).contains("\"class_name\"", "\"vendor_name\"", "\"finding_info\"", "\"affected_packages\"")
                .doesNotContain("className", "vendorName", "findingInfo", "affectedPackages");
    }

    @Test
    void olderScanExportsItsOwnToolVerdictsWithoutManual() {
        long target = imageTarget();
        long older = scan(target, "SUCCEEDED");
        long moved = finding(older, "a", "1", "CVE-2026-1", "HIGH", "UNREACHABLE", "UNREVIEWED");
        long manual = finding(older, "b", "1", "CVE-2026-2", "HIGH", "NOT_ANALYZED", "UNREVIEWED");
        // 사람 판정이 현재 판정이 된 경우 (API-06 예외): 도구 판정을 끄고 MANUAL을 켠다
        jdbc.update("UPDATE reach_verdicts SET is_current = false WHERE finding_id = ?", manual);
        jdbc.update("""
                INSERT INTO reach_verdicts (finding_id, scan_id, status, method, summary, is_current, analyzed_at,
                                            created_by_user_id)
                VALUES (?, ?, 'UNREACHABLE', 'MANUAL', 'manual', true, now(), 1)
                """, manual, older);
        // 다음 스캔에 moved가 다시 나와 판정이 바뀌고 last_scan_id가 새 스캔으로 옮겨진다
        long newer = scan(target, "SUCCEEDED");
        jdbc.update("UPDATE reach_verdicts SET is_current = false WHERE finding_id = ?", moved);
        verdict(moved, newer, "REACHABLE");
        jdbc.update("UPDATE reach_findings SET last_scan_id = ? WHERE finding_id = ?", newer, moved);

        var olderItems = list(older).items();
        assertThat(olderItems).extracting(item -> item.unmapped().reach().status())
                .containsExactly("UNREACHABLE", "NOT_ANALYZED");
        var newerItems = list(newer).items();
        assertThat(newerItems).hasSize(1);
        assertThat(newerItems.get(0).findingInfo().uid()).isEqualTo(String.valueOf(moved));
        assertThat(newerItems.get(0).unmapped().reach().status()).isEqualTo("REACHABLE");
    }

    @Test
    void statusFiltersByTheScansVerdict() {
        long id = scan(imageTarget(), "SUCCEEDED");
        long reachable = finding(id, "a", "1", "CVE-2026-1", "HIGH", "REACHABLE", "UNREVIEWED");
        finding(id, "b", "1", "CVE-2026-2", "HIGH", "UNREACHABLE", "UNREVIEWED");
        long unknown = finding(id, "c", "1", "CVE-2026-3", "LOW", "UNKNOWN", "UNREVIEWED");

        var page = service.ocsf("admin", id, List.of("REACHABLE", "UNKNOWN"), null, null);
        assertThat(uids(page)).containsExactly(String.valueOf(reachable), String.valueOf(unknown));
        assertError(() -> service.ocsf("admin", id, List.of("reachable"), null, null), ErrorCode.INVALID_INPUT);
    }

    @Test
    void cursorPagesByFindingIdAndIsBoundToTheFilter() {
        long id = scan(imageTarget(), "SUCCEEDED");
        long a = finding(id, "a", "1", "CVE-2026-1", "HIGH", "UNREACHABLE", "UNREVIEWED");
        long b = finding(id, "b", "1", "CVE-2026-2", "HIGH", "UNREACHABLE", "UNREVIEWED");
        long c = finding(id, "c", "1", "CVE-2026-3", "HIGH", "UNREACHABLE", "UNREVIEWED");

        var first = service.ocsf("admin", id, null, 2, null);
        assertThat(uids(first)).containsExactly(String.valueOf(a), String.valueOf(b));
        assertThat(first.hasNext()).isTrue();
        var second = service.ocsf("admin", id, null, 2, first.nextCursor());
        assertThat(uids(second)).containsExactly(String.valueOf(c));
        assertThat(second.hasNext()).isFalse();
        assertThat(second.nextCursor()).isNull();

        assertError(() -> service.ocsf("admin", id, List.of("UNREACHABLE"), 2, first.nextCursor()),
                ErrorCode.INVALID_INPUT);
        assertError(() -> service.ocsf("admin", id, null, 2, "not a cursor"), ErrorCode.INVALID_INPUT);
        assertError(() -> service.ocsf("admin", id, null, 0, null), ErrorCode.INVALID_INPUT);
        assertError(() -> service.ocsf("admin", id, null, 101, null), ErrorCode.INVALID_INPUT);
    }

    @Test
    void repoTargetUidIsNamePathAndCommit() {
        long api = scan(repoTarget(null), "SUCCEEDED");
        finding(api, "a", "1", "CVE-2026-1", "HIGH", "UNREACHABLE", "UNREVIEWED");
        long chat = scan(repoTarget("chat-server"), "SUCCEEDED");
        finding(chat, "a", "1", "CVE-2026-1", "HIGH", "UNREACHABLE", "UNREVIEWED");

        assertThat(list(api).items().get(0).resources())
                .containsExactly(new ReachOcsfFindingResponse.Resource("service-backend@" + COMMIT));
        assertThat(list(chat).items().get(0).resources())
                .containsExactly(new ReachOcsfFindingResponse.Resource("service-backend/chat-server@" + COMMIT));
    }

    private static void assertError(org.assertj.core.api.ThrowableAssert.ThrowingCallable call, ErrorCode code) {
        assertThatThrownBy(call).satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(code));
    }

    private ReachOcsfPageResponse list(long scanId) {
        return service.ocsf("admin", scanId, null, null, null);
    }

    private static List<String> uids(ReachOcsfPageResponse page) {
        return page.items().stream().map(item -> item.findingInfo().uid()).toList();
    }

    private static long imageTarget() {
        return jdbc.queryForObject("""
                INSERT INTO reach_targets (target_type, app, image_repository, image_digest, display_name)
                VALUES ('IMAGE', 'API', 'logssey/reused-api', ?, 'reused-api') RETURNING target_id
                """, Long.class, DIGEST);
    }

    /** path가 null이면 레포 루트. chat은 chat-server (명세 3-2) */
    private static long repoTarget(String path) {
        return jdbc.queryForObject("""
                INSERT INTO reach_targets (target_type, app, repo_name, repo_path, repo_commit, display_name)
                VALUES ('REPO', ?, 'service-backend', ?, ?, 'service-backend') RETURNING target_id
                """, Long.class, path == null ? "API" : "CHAT", path, COMMIT);
    }

    /** 상태에 맞게 시각과 실패 사유를 채운다 (V34 CHECK: 끝난 스캔만 finished_at, FAILED는 failure_code) */
    private static long scan(long targetId, String status) {
        boolean finished = status.equals("SUCCEEDED") || status.equals("FAILED");
        boolean failed = status.equals("FAILED");
        return jdbc.queryForObject("""
                INSERT INTO reach_scans (target_id, scan_status, trigger_type, requested_by_kind, started_at,
                                         finished_at, failure_code, failure_stage)
                VALUES (?, ?, 'MANUAL', 'SYSTEM', now(), CASE WHEN ? THEN now() END, ?, ?)
                RETURNING scan_id
                """, Long.class, targetId, status, finished, failed ? "E-L2-01" : null, failed ? "L2" : null);
    }

    /** Finding + 그 스캔의 현재 판정 + 검토 한 벌. 검토 상태가 UNREVIEWED가 아니면 admin이 같은 판정으로 검토 */
    private static long finding(long scanId, String name, String version, String cve, String severity, String status,
                                String reviewState) {
        long id = jdbc.queryForObject("""
                INSERT INTO reach_findings (target_id, purl, component_name, component_version, ecosystem,
                                            vulnerability_id, severity, sources, deployment, last_scan_id,
                                            first_seen_at, last_seen_at)
                SELECT target_id, 'pkg:maven/org.example/' || ? || '@' || ?, ?, ?, 'maven', ?, ?, ARRAY['TRIVY'],
                       'RUNNING', scan_id, now(), now()
                FROM reach_scans WHERE scan_id = ? RETURNING finding_id
                """, Long.class, name, version, name, version, cve, severity, scanId);
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
