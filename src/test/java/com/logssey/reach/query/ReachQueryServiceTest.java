package com.logssey.reach.query;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.query.dto.ReachFindingDetailResponse;
import com.logssey.reach.query.dto.ReachFindingPageResponse;
import com.logssey.reach.query.dto.ReachFindingResponse;
import com.logssey.reach.query.dto.ReachSummaryResponse;

import java.util.ArrayList;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReachQueryServiceTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final ReachFindingFilter ALL = new ReachFindingFilter(null, null, null, null, null);
    private static JdbcTemplate jdbc;
    private ReachQueryService service;
    private long scan;

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
        scan = scan(target("sha256:a"), "SUCCEEDED", 1);
        service = new ReachQueryService(new ReachQueryRepository(JdbcClient.create(jdbc)));
    }

    @Test
    void requiresAdmin() {
        assertError(() -> service.findings(null, ALL, null, null, null), ErrorCode.UNAUTHENTICATED);
        assertError(() -> service.findings("nobody", ALL, null, null, null), ErrorCode.FORBIDDEN);
        assertError(() -> service.summary("nobody", null, null, null, null), ErrorCode.FORBIDDEN);
        assertError(() -> service.finding("nobody", 1, null), ErrorCode.FORBIDDEN);
    }

    @Test
    void listsOnlyTheLatestSucceededScanOfEachTarget() {
        long target = target("sha256:b");
        long old = scan(target, "SUCCEEDED", 3);
        long latest = scan(target, "SUCCEEDED", 2);
        long failed = scan(target, "FAILED", 1);
        finding(old, "lib", "CVE-2026-1", "HIGH", "REACHABLE", "UNREVIEWED");
        finding(latest, "lib", "CVE-2026-2", "HIGH", "REACHABLE", "UNREVIEWED");
        finding(failed, "lib", "CVE-2026-3", "HIGH", "REACHABLE", "UNREVIEWED");

        assertThat(cves(service.findings("admin", ALL, null, null, null))).containsExactly("CVE-2026-2");
        assertThat(service.summary("admin", null, null, null, null).totals().findings()).isEqualTo(1);
    }

    @Test
    void prScansStayOutOfTheListAndSummary() {
        finding(scan(target("sha256:b"), "SUCCEEDED", 2), "lib", "CVE-2026-1", "HIGH", "REACHABLE", "UNREVIEWED");
        // PR 스캔만 있는 대상은 기준 범위에 없다 (ARD SR-09)
        finding(scan(target("sha256:c"), "SUCCEEDED", 1, "PR"), "lib", "CVE-2026-2", "HIGH", "REACHABLE", "UNREVIEWED");
        // 같은 대상을 나중에 PR로 다시 스캔해 last_scan_id가 PR 스캔이 되어도 기준 스캔의 Finding은 남는다
        long mixed = target("sha256:d");
        long manual = scan(mixed, "SUCCEEDED", 3);
        long id = finding(manual, "lib", "CVE-2026-3", "HIGH", "REACHABLE", "UNREVIEWED");
        long pr = scan(mixed, "SUCCEEDED", 1, "PR");
        jdbc.update("""
                INSERT INTO reach_verdicts (finding_id, scan_id, status, method, summary, engine, evidence_hash, is_current, analyzed_at)
                VALUES (?, ?, 'REACHABLE', 'CALLGRAPH', 'test', '{}', 'h', false, now())
                """, id, pr);
        jdbc.update("UPDATE reach_findings SET last_scan_id = ? WHERE finding_id = ?", pr, id);

        var page = service.findings("admin", ALL, null, null, null);
        assertThat(cves(page)).containsExactly("CVE-2026-1", "CVE-2026-3");
        assertThat(page.items().get(1).scanId()).isEqualTo(manual);
        assertThat(service.summary("admin", null, null, null, null).totals().findings()).isEqualTo(2);
    }

    @Test
    void scanIdAndTargetNarrowTheScope() {
        long a = target("sha256:b");
        long old = scan(a, "SUCCEEDED", 3);
        long latest = scan(a, "SUCCEEDED", 2);
        finding(old, "lib", "CVE-2026-1", "HIGH", "REACHABLE", "UNREVIEWED");
        finding(latest, "lib", "CVE-2026-2", "HIGH", "REACHABLE", "UNREVIEWED");
        finding(scan(target("sha256:c"), "SUCCEEDED", 2), "lib", "CVE-2026-3", "HIGH", "REACHABLE", "UNREVIEWED");
        long prTarget = target("sha256:d");
        long pr = scan(prTarget, "SUCCEEDED", 1, "PR");
        finding(pr, "lib", "CVE-2026-4", "HIGH", "REACHABLE", "UNREVIEWED");

        assertThat(cves(service.findings("admin", scope(null, a), null, null, null))).containsExactly("CVE-2026-2");
        var oldPage = service.findings("admin", scope(old, null), null, null, null);
        assertThat(cves(oldPage)).containsExactly("CVE-2026-1");
        assertThat(oldPage.items().getFirst().scanId()).isEqualTo(old);
        // PR 스캔은 기준 범위에 없지만 scanId로 지정하면 본다 (API-12 findingsUrl)
        assertThat(cves(service.findings("admin", scope(pr, null), null, null, null))).containsExactly("CVE-2026-4");
        assertThat(cves(service.findings("admin", scope(old, a), null, null, null))).containsExactly("CVE-2026-1");

        var summary = service.summary("admin", a, null, null, null);
        assertThat(summary.scope()).isEqualTo(new ReachSummaryResponse.Scope(a, latest));
        assertThat(summary.totals().findings()).isEqualTo(1);
        assertThat(service.summary("admin", null, pr, null, null).scope()).isEqualTo(new ReachSummaryResponse.Scope(prTarget, pr));
        assertThat(service.summary("admin", null, null, null, null).scope()).isEqualTo(new ReachSummaryResponse.Scope(null, null));
        long empty = target("sha256:e");
        var none = service.summary("admin", empty, null, null, null);
        assertThat(none.scope()).isEqualTo(new ReachSummaryResponse.Scope(empty, null));
        assertThat(none.totals().findings()).isZero();
    }

    @Test
    void scopeParametersAreChecked() {
        long a = target("sha256:b");
        long b = target("sha256:c");
        long scanA = scan(a, "SUCCEEDED", 2);
        finding(scanA, "lib", "CVE-2026-1", "HIGH", "REACHABLE", "UNREVIEWED");
        finding(scanA, "lib2", "CVE-2026-2", "HIGH", "REACHABLE", "UNREVIEWED");
        long running = jdbc.queryForObject("""
                INSERT INTO reach_scans (target_id, scan_status, trigger_type, requested_by_kind)
                VALUES (?, 'RUNNING', 'MANUAL', 'SYSTEM') RETURNING scan_id
                """, Long.class, a);

        assertError(() -> service.findings("admin", scope(999_999L, null), null, null, null), ErrorCode.NOT_FOUND);
        assertError(() -> service.findings("admin", scope(null, 999_999L), null, null, null), ErrorCode.NOT_FOUND);
        assertError(() -> service.findings("admin", scope(running, null), null, null, null), ErrorCode.CONFLICT);
        assertError(() -> service.findings("admin", scope(scanA, b), null, null, null), ErrorCode.INVALID_INPUT);
        assertError(() -> service.summary("admin", b, scanA, null, null), ErrorCode.INVALID_INPUT);
        // 커서는 범위와도 묶인다
        String cursor = service.findings("admin", scope(scanA, null), 1, null, null).nextCursor();
        assertError(() -> service.findings("admin", scope(null, a), 1, cursor, null), ErrorCode.INVALID_INPUT);
        assertThat(service.findings("admin", scope(scanA, null), 1, cursor, null).items()).hasSize(1);
    }

    @Test
    void sortsByStatusThenSeverityThenCveNumber() {
        finding(scan, "a", "CVE-2026-13506", "HIGH", "UNREACHABLE", "UNREVIEWED");
        finding(scan, "b", "GHSA-xxxx-yyyy-zzzz", "HIGH", "UNREACHABLE", "UNREVIEWED");
        finding(scan, "c", "CVE-2026-8763", "HIGH", "UNREACHABLE", "UNREVIEWED");
        finding(scan, "d", "CVE-2026-1", "CRITICAL", "UNREACHABLE", "UNREVIEWED");
        finding(scan, "e", "CVE-2026-2", "LOW", "REACHABLE", "UNREVIEWED");

        // 명세 2-5: 문자열로 비교하면 13506이 8763보다 앞에 온다. CVE가 아닌 ID는 맨 뒤
        assertThat(cves(service.findings("admin", ALL, null, null, null))).containsExactly(
                "CVE-2026-2", "CVE-2026-1", "CVE-2026-8763", "CVE-2026-13506", "GHSA-xxxx-yyyy-zzzz");
    }

    @Test
    void filterValuesAreOrWithinAFieldAndAndAcrossFields() {
        finding(scan, "a", "CVE-2026-1", "HIGH", "REACHABLE", "UNREVIEWED");
        finding(scan, "b", "CVE-2026-2", "LOW", "UNKNOWN", "UNREVIEWED");
        finding(scan, "c", "CVE-2026-3", "HIGH", "UNREACHABLE", "UNREVIEWED");

        var either = new ReachFindingFilter(List.of("REACHABLE", "UNKNOWN"), null, null, null, null);
        assertThat(cves(service.findings("admin", either, null, null, null))).containsExactly("CVE-2026-1", "CVE-2026-2");

        var both = new ReachFindingFilter(List.of("REACHABLE", "UNKNOWN"), List.of("HIGH"), null, null, " 2026-1 ");
        assertThat(cves(service.findings("admin", both, null, null, null))).containsExactly("CVE-2026-1");
    }

    @Test
    void rejectsValuesOutsideTheSpec() {
        assertError(() -> new ReachFindingFilter(List.of("REACKABLE"), null, null, null, null), ErrorCode.INVALID_INPUT);
        assertError(() -> service.findings("admin", ALL, 101, null, null), ErrorCode.INVALID_INPUT);
        assertError(() -> service.findings("admin", ALL, null, "not-a-cursor", null), ErrorCode.INVALID_INPUT);
        assertError(() -> service.findings("admin", ALL, null, null, "matrix"), ErrorCode.INVALID_INPUT);
        assertError(() -> service.summary("admin", null, null, null, List.of("total")), ErrorCode.INVALID_INPUT);
    }

    @Test
    void cursorVisitsEveryFindingOnce() {
        for (int i = 1; i <= 5; i++) finding(scan, "lib" + i, "CVE-2026-" + i, "HIGH", "UNREACHABLE", "UNREVIEWED");

        var seen = new ArrayList<String>();
        String cursor = null;
        do {
            var page = service.findings("admin", ALL, 2, cursor, "total");
            assertThat(page.totalCount()).isEqualTo(5);
            seen.addAll(cves(page));
            cursor = page.nextCursor();
        } while (cursor != null);

        assertThat(seen).containsExactly("CVE-2026-1", "CVE-2026-2", "CVE-2026-3", "CVE-2026-4", "CVE-2026-5");
    }

    @Test
    void cursorCannotBeReusedWithAnotherFilter() {
        for (int i = 1; i <= 3; i++) finding(scan, "lib" + i, "CVE-2026-" + i, "HIGH", "UNREACHABLE", "UNREVIEWED");
        String cursor = service.findings("admin", ALL, 1, null, null).nextCursor();

        var other = new ReachFindingFilter(List.of("UNREACHABLE"), null, null, null, null);
        assertError(() -> service.findings("admin", other, 1, cursor, null), ErrorCode.INVALID_INPUT);
    }

    @Test
    void summaryMatchesTheListAndLeavesRatioEmptyWithoutJudgedFindings() {
        finding(scan, "a", "CVE-2026-1", "CRITICAL", "UNREACHABLE", "CONFIRMED");
        finding(scan, "b", "CVE-2026-2", "HIGH", "REACHABLE", "UNREVIEWED");
        finding(scan, "c", "CVE-2026-3", "HIGH", "NOT_ANALYZED", "UNREVIEWED");

        var summary = service.summary("admin", null, null, null, List.of("matrix"));
        assertThat(summary.totals().findings()).isEqualTo(service.findings("admin", ALL, null, null, "total").totalCount());
        assertThat(summary.byStatus()).containsEntry("UNREACHABLE", 1L).containsEntry("UNKNOWN", 0L);
        assertThat(summary.byNotAnalyzedReason()).containsEntry("OS_PACKAGE", 1L);
        assertThat(summary.severityByStatus().get("HIGH")).containsOnlyKeys("REACHABLE", "NOT_ANALYZED");
        assertThat(summary.noiseReduction().ratio()).isEqualTo(0.5);      // UNREACHABLE 1 / 판정 2
        assertThat(summary.coverage().ratio()).isEqualTo(0.667);          // 판정 2 / 전체 3

        var empty = service.summary("admin", null, null, List.of("RUNNING"), null);  // 테스트 Finding은 전부 deployment UNKNOWN
        assertThat(empty.totals().findings()).isZero();
        assertThat(empty.noiseReduction().ratio()).isNull();
        assertThat(empty.severityByStatus()).isNull();
    }

    @Test
    void detailOrdersEvidenceAndListsOtherFindingsOfTheSameCve() {
        long id = finding(scan, "jackson-core", "CVE-2026-1", "HIGH", "UNREACHABLE", "CONFIRMED");
        long same = finding(scan, "jackson-databind", "CVE-2026-1", "HIGH", "UNREACHABLE", "UNREVIEWED");
        long verdict = jdbc.queryForObject("SELECT verdict_id FROM reach_verdicts WHERE finding_id = ?", Long.class, id);
        jdbc.update("""
                INSERT INTO reach_evidence (verdict_id, ord, kind, summary, detail) VALUES
                    (?, 2, 'PATH', 'second', '{"path": ["Main.run", "Lib.parse"]}'),
                    (?, 1, 'NOTE', 'first', '{}')
                """, verdict, verdict);

        var detail = service.finding("admin", id, null);
        var evidence = detail.verdict().evidence();
        assertThat(evidence.get(0).get("summary").asString()).isEqualTo("first");
        assertThat(evidence.get(1).get("path").get(1).asString()).isEqualTo("Lib.parse");   // detail 키가 합쳐진다
        assertThat(detail.sameCveFindings()).containsExactly(same);
        assertThat(detail.review().reviewer().name()).isEqualTo("Admin");
        assertThat(service.finding("admin", same, null).review().reviewer()).isNull();

        assertError(() -> service.finding("admin", 999, null), ErrorCode.NOT_FOUND);
    }

    @Test
    void reviewHistoryIsNewestFirstAndOnlyWhenIncluded() {
        long id = finding(scan, "jackson-core", "CVE-2026-1", "HIGH", "UNREACHABLE", "UNREVIEWED");
        long other = finding(scan, "jackson-databind", "CVE-2026-2", "HIGH", "UNREACHABLE", "UNREVIEWED");
        // 사람 저장 두 번 뒤에 서버가 되돌린 기록 (admin은 user_id 1)
        jdbc.update("""
                INSERT INTO reach_review_history (finding_id, version, review_state, status, note, reviewer_user_id,
                                                  reviewed_at, change_kind) VALUES
                    (?, 2, 'PROVISIONAL', 'UNREACHABLE', 'first', 1, now() - interval '2 hours', 'HUMAN'),
                    (?, 3, 'CONFIRMED', 'UNREACHABLE', 'second', 1, now() - interval '1 hour', 'HUMAN'),
                    (?, 4, 'UNREVIEWED', NULL, NULL, NULL, NULL, 'RESET'),
                    (?, 2, 'PROVISIONAL', 'UNKNOWN', 'other', 1, now(), 'HUMAN')
                """, id, id, id, other);

        assertThat(service.finding("admin", id, null).review().history()).isNull();

        var history = service.finding("admin", id, List.of("reviewHistory")).review().history();
        assertThat(history).extracting(ReachFindingDetailResponse.History::version).containsExactly(4, 3, 2);
        assertThat(history.get(0).changeKind()).isEqualTo("RESET");
        assertThat(history.get(0).reviewer()).isNull();
        assertThat(history.get(1).reviewer().name()).isEqualTo("Admin");
        assertThat(history.get(1).note()).isEqualTo("second");

        long none = finding(scan, "netty", "CVE-2026-3", "LOW", "UNREACHABLE", "UNREVIEWED");
        assertThat(service.finding("admin", none, List.of("reviewHistory")).review().history()).isEmpty();
    }

    @Test
    void includeAcceptsTheFourSpecValues() {
        long id = finding(scan, "jackson-core", "CVE-2026-1", "HIGH", "UNREACHABLE", "UNREVIEWED");

        // RULE·vulnFunctions·verdictHistory는 받기만 하고 아직 채우지 않는다
        var detail = service.finding("admin", id, List.of("RULE", "vulnFunctions", "verdictHistory"));
        assertThat(detail.review().history()).isNull();
        assertError(() -> service.finding("admin", id, List.of("bogus")), ErrorCode.INVALID_INPUT);
        assertError(() -> service.finding("admin", id, List.of("reviewhistory")), ErrorCode.INVALID_INPUT);
    }

    @Test
    void carriedFromPointsToThePreviousFindingsReview() {
        long previous = finding(scan, "jackson-core", "CVE-2026-1", "HIGH", "UNREACHABLE", "CONFIRMED");
        long newer = scan(target("sha256:b"), "SUCCEEDED", 0);
        long carried = finding(newer, "jackson-core", "CVE-2026-1", "HIGH", "UNREACHABLE", "CONFIRMED");
        jdbc.update("UPDATE reach_reviews SET reviewed_at = now() - interval '3 days' WHERE finding_id = ?", previous);
        jdbc.update("UPDATE reach_reviews SET carried_from_finding_id = ?, carried_from_scan_id = ? WHERE finding_id = ?",
                previous, scan, carried);

        var carriedFrom = service.finding("admin", carried, null).review().carriedFrom();
        assertThat(carriedFrom.findingId()).isEqualTo(previous);
        assertThat(carriedFrom.scanId()).isEqualTo(scan);
        assertThat(carriedFrom.reviewedAt()).isEqualTo(service.finding("admin", previous, null).review().reviewedAt());
        assertThat(service.finding("admin", previous, null).review().carriedFrom()).isNull();
    }

    private static void assertError(org.assertj.core.api.ThrowableAssert.ThrowingCallable call, ErrorCode code) {
        assertThatThrownBy(call).satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(code));
    }

    private static List<String> cves(ReachFindingPageResponse page) {
        return page.items().stream().map(ReachFindingResponse::vulnerability).map(ReachFindingResponse.Vulnerability::id).toList();
    }

    /** 기준 범위만 지정한 필터 */
    private static ReachFindingFilter scope(Long scanId, Long target) {
        return new ReachFindingFilter(null, null, null, null, null, scanId, target);
    }

    private static long target(String digest) {
        return jdbc.queryForObject("""
                INSERT INTO reach_targets (target_type, app, image_repository, image_digest, display_name)
                VALUES ('IMAGE', 'API', 'reused-api', ?, 'api') RETURNING target_id
                """, Long.class, digest);
    }

    /** hoursAgo 시간 전에 끝난 스캔. FAILED는 failure_code가 있어야 한다 (V34 CHECK) */
    private static long scan(long targetId, String status, int hoursAgo) {
        return scan(targetId, status, hoursAgo, "MANUAL");
    }

    private static long scan(long targetId, String status, int hoursAgo, String trigger) {
        return jdbc.queryForObject("""
                INSERT INTO reach_scans (target_id, scan_status, trigger_type, requested_by_kind, failure_code, finished_at)
                VALUES (?, ?, ?, 'SYSTEM', ?, now() - make_interval(hours => ?)) RETURNING scan_id
                """, Long.class, targetId, status, trigger, status.equals("FAILED") ? "TEST" : null, hoursAgo);
    }

    /** Finding + 현재 판정 + 검토 한 벌. NOT_ANALYZED면 방식 없이 사유 OS_PACKAGE, 검토 상태가 UNREVIEWED가 아니면 admin이 같은 판정으로 검토 */
    private static long finding(long scanId, String component, String cve, String severity, String status, String reviewState) {
        long id = jdbc.queryForObject("""
                INSERT INTO reach_findings (target_id, purl, component_name, component_version, ecosystem,
                                            vulnerability_id, severity, sources, last_scan_id, first_seen_at, last_seen_at)
                SELECT target_id, 'pkg:maven/test/' || ? || '@1', ?, '1', 'maven', ?, ?, ARRAY['TRIVY'], scan_id, now(), now()
                FROM reach_scans WHERE scan_id = ? RETURNING finding_id
                """, Long.class, component, component, cve, severity, scanId);
        boolean notAnalyzed = status.equals("NOT_ANALYZED");
        jdbc.update("""
                INSERT INTO reach_verdicts (finding_id, scan_id, status, method, not_analyzed_reason, summary,
                                            engine, evidence_hash, is_current, analyzed_at)
                VALUES (?, ?, ?, ?, ?, 'test', '{}', 'h', true, now())
                """, id, scanId, status, notAnalyzed ? null : "CALLGRAPH", notAnalyzed ? "OS_PACKAGE" : null);
        boolean human = !reviewState.equals("UNREVIEWED");
        jdbc.update("""
                INSERT INTO reach_reviews (finding_id, review_state, status, note, reviewer_user_id, reviewed_at)
                VALUES (?, ?, ?, ?, ?, CASE WHEN ? THEN now() END)
                """, id, reviewState, human ? status : null, human ? "checked" : null, human ? 1L : null, human);
        return id;
    }
}
