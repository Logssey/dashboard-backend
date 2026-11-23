package com.logssey.reach.query;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ReachTestProperties;
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
                + "reach_findings, reach_scans, reach_targets, reach_workloads, reach_workload_observations, "
                + "dashboard_users RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO dashboard_users (login_id, password_hash, display_name, role) "
                + "VALUES ('admin', 'h', 'Admin', 'ADMIN')");
        scan = scan(target("sha256:a"), "SUCCEEDED", 1);
        service = new ReachQueryService(new ReachQueryRepository(JdbcClient.create(jdbc)), ReachTestProperties.REUSED);
    }

    @Test
    void requiresAdmin() {
        assertError(() -> service.findings(null, ALL, null, null, null), ErrorCode.UNAUTHENTICATED);
        assertError(() -> service.findings("nobody", ALL, null, null, null), ErrorCode.FORBIDDEN);
        assertError(() -> service.summary("nobody", null, null, null, null), ErrorCode.FORBIDDEN);
        assertError(() -> service.finding("nobody", 1, null), ErrorCode.FORBIDDEN);
    }

    @Test
    void listsOnlyTheLatestSucceededScanOfEachAppAndKind() {
        // 이미지를 다시 빌드하면 digest마다 대상이 생긴다. 기본 범위는 app·대상 종류마다 최신 스캔 하나라 옛 이미지는 빠진다
        long olderImage = target("sha256:b");   // API 이미지. reset()의 sha256:a 스캔(1시간 전)보다 먼저 끝났다
        finding(scan(olderImage, "SUCCEEDED", 5), "lib", "CVE-2026-1", "HIGH", "REACHABLE", "UNREVIEWED");
        finding(scan, "lib", "CVE-2026-2", "HIGH", "REACHABLE", "UNREVIEWED");
        long web = target("sha256:c", "WEB");
        long old = scan(web, "SUCCEEDED", 3);
        long latest = scan(web, "SUCCEEDED", 2);
        long failed = scan(web, "FAILED", 1);
        finding(old, "lib", "CVE-2026-3", "HIGH", "REACHABLE", "UNREVIEWED");
        finding(latest, "lib", "CVE-2026-4", "HIGH", "REACHABLE", "UNREVIEWED");
        finding(failed, "lib", "CVE-2026-5", "HIGH", "REACHABLE", "UNREVIEWED");
        // 같은 app이어도 레포 대상은 따로 센다 (명세 3-2: CHAT은 레포 + 이미지)
        finding(scan(repoTarget("API", "1".repeat(40)), "SUCCEEDED", 4), "lib", "CVE-2026-6", "HIGH", "REACHABLE", "UNREVIEWED");

        assertThat(cves(service.findings("admin", ALL, null, null, null)))
                .containsExactly("CVE-2026-2", "CVE-2026-4", "CVE-2026-6");
        assertThat(service.summary("admin", null, null, null, null).totals().findings()).isEqualTo(3);
        // 옛 이미지는 target으로 지정하면 본다
        assertThat(cves(service.findings("admin", scope(null, olderImage), null, null, null))).containsExactly("CVE-2026-1");
    }

    @Test
    void prScansStayOutOfTheListAndSummary() {
        finding(scan(target("sha256:b", "WEB"), "SUCCEEDED", 2), "lib", "CVE-2026-1", "HIGH", "REACHABLE", "UNREVIEWED");
        // PR 스캔만 있는 대상은 더 늦게 끝났어도 기준 범위에 없다 (ARD SR-09)
        finding(scan(target("sha256:c", "WEB"), "SUCCEEDED", 1, "PR"), "lib", "CVE-2026-2", "HIGH", "REACHABLE", "UNREVIEWED");
        // 같은 대상을 나중에 PR로 다시 스캔해 last_scan_id가 PR 스캔이 되어도 기준 스캔의 Finding은 남는다
        long mixed = target("sha256:d", "CHAT");
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
    void aPastScanShowsItsOwnToolVerdictsNotTodays() {
        long a = target("sha256:b");
        long old = scan(a, "SUCCEEDED", 3);
        long id = finding(old, "lib", "CVE-2026-1", "HIGH", "UNREACHABLE", "UNREVIEWED");
        long other = finding(old, "zlib", "CVE-2026-2", "HIGH", "NOT_ANALYZED", "UNREVIEWED");
        // a later scan of the same image says REACHABLE (today's verdict). A person judged the NOT_ANALYZED one by hand
        long latest = scan(a, "SUCCEEDED", 1);
        jdbc.update("UPDATE reach_verdicts SET is_current = false WHERE finding_id IN (?, ?)", id, other);
        jdbc.update("""
                INSERT INTO reach_verdicts (finding_id, scan_id, status, method, summary, engine, evidence_hash, is_current, analyzed_at)
                VALUES (?, ?, 'REACHABLE', 'CALLGRAPH', 'later', '{}', 'h2', true, now())
                """, id, latest);
        jdbc.update("""
                INSERT INTO reach_verdicts (finding_id, scan_id, status, not_analyzed_reason, summary, engine, evidence_hash, is_current, analyzed_at)
                VALUES (?, ?, 'NOT_ANALYZED', 'OS_PACKAGE', 'later', '{}', 'h', false, now())
                """, other, latest);
        jdbc.update("""
                INSERT INTO reach_verdicts (finding_id, scan_id, status, method, summary, is_current, analyzed_at, created_by_user_id)
                VALUES (?, ?, 'UNREACHABLE', 'MANUAL', 'by hand', true, now(), 1)
                """, other, latest);

        // the default scope and target are today: REACHABLE and the human verdict
        assertThat(service.findings("admin", ALL, null, null, null).items())
                .extracting(i -> i.vulnerability().id() + ":" + i.verdict().status())
                .containsExactly("CVE-2026-1:REACHABLE", "CVE-2026-2:UNREACHABLE");
        // the old scan (e.g. a PR check result, a scan in the history) shows what that scan said
        var then = service.findings("admin", scope(old, null), null, null, null);
        assertThat(then.items()).extracting(i -> i.vulnerability().id() + ":" + i.verdict().status())
                .containsExactly("CVE-2026-1:UNREACHABLE", "CVE-2026-2:NOT_ANALYZED");
        var summary = service.summary("admin", null, old, null, null);
        assertThat(summary.totals().findings()).isEqualTo(2);
        assertThat(service.findings("admin", new ReachFindingFilter(List.of("REACHABLE"), null, null, null, null, old, null, null, null),
                null, null, null).items()).isEmpty();
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
        finding(scan, "f", "CVE-2026-12345678901", "HIGH", "UNREACHABLE", "UNREVIEWED");

        // 명세 2-5: 문자열로 비교하면 13506이 8763보다 앞에 온다. CVE가 아닌 ID와 int를 넘는 번호는 맨 뒤
        assertThat(cves(service.findings("admin", ALL, null, null, null))).containsExactly(
                "CVE-2026-2", "CVE-2026-1", "CVE-2026-8763", "CVE-2026-13506", "GHSA-xxxx-yyyy-zzzz", "CVE-2026-12345678901");
        String cursor = service.findings("admin", ALL, 5, null, null).nextCursor();
        assertThat(cves(service.findings("admin", ALL, 5, cursor, null))).containsExactly("CVE-2026-12345678901");
    }

    @Test
    void runningImagesComeFirstThenUnknownThenNotRunning() {
        // 기본 범위의 대상 셋: API 이미지(실행 중), WEB 이미지(실행 안 함), CHAT 레포(확인 못 함)
        finding(scan, "a", "CVE-2026-1", "LOW", "UNREACHABLE", "UNREVIEWED");
        long web = scan(target("sha256:b", "WEB"), "SUCCEEDED", 2);
        finding(web, "b", "CVE-2026-2", "CRITICAL", "REACHABLE", "UNREVIEWED");
        long chat = scan(repoTarget("CHAT", "1".repeat(40)), "SUCCEEDED", 2);
        finding(chat, "c", "CVE-2026-3", "CRITICAL", "REACHABLE", "UNREVIEWED");
        finding(scan, "d", "CVE-2026-4", "HIGH", "REACHABLE", "UNREVIEWED");
        jdbc.update("UPDATE reach_findings f SET deployment = 'RUNNING' FROM reach_targets t "
                + "WHERE t.target_id = f.target_id AND t.image_digest = 'sha256:a'");
        jdbc.update("UPDATE reach_findings f SET deployment = 'NOT_RUNNING' FROM reach_targets t "
                + "WHERE t.target_id = f.target_id AND t.image_digest = 'sha256:b'");

        // 실행 중 이미지 안에서는 지금처럼 상태 → 심각도. 도달 가능 CRITICAL이어도 실행 중이 아니면 뒤에 온다
        var expected = List.of("CVE-2026-4", "CVE-2026-1", "CVE-2026-3", "CVE-2026-2");
        assertThat(cves(service.findings("admin", ALL, null, null, null))).containsExactlyElementsOf(expected);

        // 커서가 배포 경계를 넘어도 빠지거나 겹치지 않는다
        var seen = new ArrayList<String>();
        String cursor = null;
        do {
            var page = service.findings("admin", ALL, 1, cursor, null);
            seen.addAll(cves(page));
            cursor = page.nextCursor();
        } while (cursor != null);
        assertThat(seen).containsExactlyElementsOf(expected);

        // 배포 순위가 없던 커서(정렬 키 5개 + 필터)는 400
        String old = java.util.Base64.getUrlEncoder().withoutPadding()
                .encodeToString(("0,0,2026,1,1," + ALL.fingerprint()).getBytes());
        assertError(() -> service.findings("admin", ALL, 1, old, null), ErrorCode.INVALID_INPUT);
    }

    @Test
    void nullInsideAnArrayColumnIsSkipped() {
        long id = finding(scan, "a", "CVE-2026-1", "HIGH", "REACHABLE", "UNREVIEWED");
        jdbc.update("UPDATE reach_findings SET fixed_versions = ARRAY['1.0.1', NULL] WHERE finding_id = ?", id);

        assertThat(service.findings("admin", ALL, null, null, null).items().getFirst().vulnerability().fixedVersions())
                .containsExactly("1.0.1");
        assertThat(service.finding("admin", id, null).vulnerability().fixedVersions()).containsExactly("1.0.1");
    }

    @Test
    void detailReturnsStoredScannerFieldsAndVulnFunctionIds() {
        long id = finding(scan, "a", "CVE-2026-1", "HIGH", "REACHABLE", "UNREVIEWED");
        long empty = finding(scan, "b", "CVE-2026-2", "HIGH", "REACHABLE", "UNREVIEWED");
        jdbc.update("""
                UPDATE reach_findings SET component_path = 'app.jar/BOOT-INF/lib/a-1.jar', vuln_description = 'desc',
                       cwe_ids = ARRAY['CWE-400', 'CWE-1333'], reference_urls = ARRAY['https://example.com/a']
                WHERE finding_id = ?""", id);
        jdbc.update("UPDATE reach_verdicts SET vuln_function_ids = ARRAY[3, 1] WHERE finding_id = ?", id);

        var detail = service.finding("admin", id, null);
        assertThat(detail.component().path()).isEqualTo("app.jar/BOOT-INF/lib/a-1.jar");
        assertThat(detail.vulnerability().description()).isEqualTo("desc");
        assertThat(detail.vulnerability().cwe()).containsExactly("CWE-400", "CWE-1333");
        assertThat(detail.vulnerability().references()).containsExactly("https://example.com/a");
        assertThat(detail.verdict().vulnFunctionIds()).containsExactly(3, 1);   // 저장 순서 그대로

        var none = service.finding("admin", empty, null);   // 칸이 비면 null·빈 배열
        assertThat(none.component().path()).isNull();
        assertThat(none.vulnerability().description()).isNull();
        assertThat(none.vulnerability().cwe()).isEmpty();
        assertThat(none.vulnerability().references()).isEmpty();
        assertThat(none.verdict().vulnFunctionIds()).isEmpty();
    }

    @Test
    void listShowsHowFarL3GotNextToTheVerdictAndFiltersByIt() {
        long region = finding(scan, "a", "CVE-2026-1", "HIGH", "UNREACHABLE", "UNREVIEWED");
        long function = finding(scan, "b", "CVE-2026-2", "HIGH", "UNREACHABLE", "UNREVIEWED");
        finding(scan, "c", "CVE-2026-3", "HIGH", "REACHABLE", "UNREVIEWED");          // 띄워 본 결과 없음
        l3Run(scan);
        l3Result(region, scan, "REGION", true, false);
        l3Result(function, scan, "FUNCTION", false, true);

        var items = service.findings("admin", ALL, null, null, null).items();
        var byCve = items.stream().collect(java.util.stream.Collectors.toMap(i -> i.vulnerability().id(), i -> i));
        // L2 판정은 그대로이고 L3가 옆에 붙는다 (L2 도달 불가 + L3 구간 실행이 사람이 볼 1순위)
        assertThat(byCve.get("CVE-2026-1").verdict().status()).isEqualTo("UNREACHABLE");
        assertThat(byCve.get("CVE-2026-1").l3()).isEqualTo(new ReachFindingResponse.L3("REGION", true, false));
        assertThat(byCve.get("CVE-2026-2").l3()).isEqualTo(new ReachFindingResponse.L3("FUNCTION", false, true));
        assertThat(byCve.get("CVE-2026-3").l3()).isNull();

        var executed = new ReachFindingFilter(null, null, null, null, null, null, null, null, List.of("REGION", "FUNCTION"));
        assertThat(cves(service.findings("admin", executed, null, null, null))).containsExactly("CVE-2026-1", "CVE-2026-2");
        var missed = new ReachFindingFilter(List.of("UNREACHABLE"), null, null, null, null, null, null, null, List.of("REGION"));
        assertThat(cves(service.findings("admin", missed, null, null, null))).containsExactly("CVE-2026-1");
        assertError(() -> new ReachFindingFilter(null, null, null, null, null, null, null, null, List.of("EXECUTED")),
                ErrorCode.INVALID_INPUT);
        // 요약 숫자는 L3와 무관하다
        assertThat(service.summary("admin", null, null, null, null).totals().findings()).isEqualTo(3);
    }

    @Test
    void detailCarriesTheL3EvidenceAndTheRunItCameFrom() {
        long id = finding(scan, "a", "CVE-2026-1", "HIGH", "UNREACHABLE", "UNREVIEWED");
        long none = finding(scan, "b", "CVE-2026-2", "HIGH", "UNREACHABLE", "UNREVIEWED");
        l3Run(scan);
        l3Result(id, scan, "REGION", true, false);

        var l3 = service.finding("admin", id, null).l3();
        assertThat(l3.reached()).isEqualTo("REGION");
        assertThat(l3.regionsChecked()).isTrue();
        assertThat(l3.startupOnly()).isFalse();
        assertThat(l3.during().get(0).asString()).isEqualTo("002");
        assertThat(l3.functions().get(0).get("function").asString()).isEqualTo("org.example.Parser#check");
        assertThat(l3.regions().get(0).get("executedLines").get(0).asInt()).isEqualTo(626);
        assertThat(l3.paths().get(0).get("reachedStep").asInt()).isEqualTo(2);
        assertThat(l3.note()).isEqualTo("checked by hand");
        assertThat(l3.run().scanId()).isEqualTo(scan);
        assertThat(l3.run().scenario()).isEqualTo("2026-11-18.1");
        assertThat(l3.run().observationMethod()).isEqualTo("COVERAGE");
        assertThat(l3.run().observedAt()).isNotNull();
        assertThat(l3.run().build().get("imageDigest").asString()).isEqualTo("sha256:a");
        assertThat(l3.run().configKeys().get(0).get("name").asString()).isEqualTo("KAKAO_STUB");
        assertThat(l3.run().invocations().get(1).get("request").asString()).isEqualTo("POST /items");
        // 검토 이력을 붙여도 남는다
        assertThat(service.finding("admin", id, List.of("reviewHistory")).l3().reached()).isEqualTo("REGION");
        assertThat(service.finding("admin", none, null).l3()).isNull();
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

    @Test
    void runningBasisUsesTheRunningImageOfEachAppFirst() {
        String running = digest('1'), built = digest('2'), chat = digest('3');
        long runningScan = scan(target(running), "SUCCEEDED", 5);
        finding(runningScan, "running-lib", "CVE-2026-0001", "HIGH", "REACHABLE", "UNREVIEWED");
        long builtScan = scan(target(built), "SUCCEEDED", 0);        // 더 최근이지만 배포되지 않은 빌드
        finding(builtScan, "built-lib", "CVE-2026-0002", "HIGH", "REACHABLE", "UNREVIEWED");
        long repoScan = scan(repoTarget("API", "c1"), "SUCCEEDED", 0);
        finding(repoScan, "repo-lib", "CVE-2026-0003", "LOW", "UNKNOWN", "UNREVIEWED");
        observe(2, new String[] {"reused-api", "logssey/reused-api:1", running},
                new String[] {"reused-chat", "logssey/reused-chat:9", chat});   // chat은 스캔이 없다

        // 기본(RUNNING): API 이미지는 실행 중 digest의 스캔, 레포는 그대로 최신
        assertThat(cves(service.findings("admin", ALL, null, null, null)))
                .containsExactlyInAnyOrder("CVE-2026-0001", "CVE-2026-0003");
        var summary = service.summary("admin", null, null, null, null, null);
        assertThat(summary.totals().findings()).isEqualTo(2);
        assertThat(summary.basis().requested()).isEqualTo("RUNNING");
        assertThat(summary.basis().applied()).isEqualTo("RUNNING");
        assertThat(summary.basis().scans())
                .extracting(s -> s.app() + "/" + s.targetType() + "/" + s.scanId() + "/" + s.running())
                .containsExactly("API/IMAGE/" + runningScan + "/true", "API/REPO/" + repoScan + "/false");
        assertThat(summary.basis().unscannedRunning()).singleElement().satisfies(w -> {
            assertThat(w.app()).isEqualTo("CHAT");   // 설치 설정의 이미지로 앱을 안다
            assertThat(w.name()).isEqualTo("reused-chat");
            assertThat(w.imageRepository()).isEqualTo("logssey/reused-chat");
            assertThat(w.imageDigest()).isEqualTo(chat);
        });
        // 하루 1번 재대조 대상: 실행 중인 이미지의 스캔만 (레포·배포 안 된 빌드는 아니다)
        assertThat(service.runningImageScanIds()).containsExactly(runningScan);
        // PR 검사의 기준: 그 앱의 실행 중 이미지 스캔. 실행 중이어도 스캔이 없거나(chat) 앱을 모르면 없다
        assertThat(service.runningImageScan("API")).contains(runningScan);
        assertThat(service.runningImageScan("CHAT")).isEmpty();
        assertThat(service.runningImageScan(null)).isEmpty();

        // LATEST: 지금까지처럼 앱·대상 종류마다 최신 스캔
        var latest = new ReachFindingFilter(null, null, null, null, null, null, null, "LATEST");
        assertThat(cves(service.findings("admin", latest, null, null, null)))
                .containsExactlyInAnyOrder("CVE-2026-0002", "CVE-2026-0003");
        var latestSummary = service.summary("admin", null, null, null, null, "LATEST");
        assertThat(latestSummary.basis().applied()).isEqualTo("LATEST");
        assertThat(latestSummary.basis().unscannedRunning()).isEmpty();
        assertThat(latestSummary.basis().scans()).extracting(s -> s.scanId()).contains(builtScan);

        // 커서는 basis와 묶인다 (명세 2-4)
        var page = service.findings("admin", ALL, 1, null, null);
        assertError(() -> service.findings("admin", latest, 1, page.nextCursor(), null), ErrorCode.INVALID_INPUT);
    }

    @Test
    void runningBasisFallsBackToTheLatestScanWithoutAFreshObservation() {
        String running = digest('1');
        long runningScan = scan(target(running), "SUCCEEDED", 5);
        finding(runningScan, "running-lib", "CVE-2026-0001", "HIGH", "REACHABLE", "UNREVIEWED");
        long builtScan = scan(target(digest('2')), "SUCCEEDED", 0);
        finding(builtScan, "built-lib", "CVE-2026-0002", "HIGH", "REACHABLE", "UNREVIEWED");
        observe(72, new String[] {"reused-api", "logssey/reused-api:1", running});   // 48시간이 지난 조회

        assertThat(cves(service.findings("admin", ALL, null, null, null))).containsExactly("CVE-2026-0002");
        var summary = service.summary("admin", null, null, null, null, null);
        assertThat(summary.basis().requested()).isEqualTo("RUNNING");
        assertThat(summary.basis().applied()).isEqualTo("LATEST");
        assertThat(summary.basis().unscannedRunning()).isEmpty();
        assertThat(service.runningImageScanIds()).isEmpty();   // 실행 중인 이미지를 모르면 재대조하지 않는다
        assertThat(service.runningImageScan("API")).isEmpty();   // PR 검사도 기준 없이 본다

        // L1이 꺼진 설치도 LATEST와 같다
        var noL1 = new ReachQueryService(new ReachQueryRepository(JdbcClient.create(jdbc)),
                ReachTestProperties.withL1(null, List.of()));
        assertThat(noL1.summary("admin", null, null, null, null, "RUNNING").basis().applied()).isEqualTo("LATEST");
        assertThat(noL1.runningImageScan("API")).isEmpty();
    }

    @Test
    void basisIsCheckedAndOnlyDescribesTheDefaultScope() {
        assertError(() -> service.summary("admin", null, null, null, null, "OLDEST"), ErrorCode.INVALID_INPUT);
        assertError(() -> service.findings("admin", new ReachFindingFilter(null, null, null, null, null, null, null, "x"),
                null, null, null), ErrorCode.INVALID_INPUT);
        assertThat(service.summary("admin", null, scan, null, null, null).basis()).isNull();   // scanId·target이면 basis 없음
    }

    private static String digest(char c) {
        return "sha256:" + String.valueOf(c).repeat(64);
    }

    /** reused-prod/reused 조회 한 번과 워크로드들 ({이름, 이미지, digest}) */
    private static void observe(int hoursAgo, String[]... workloads) {
        jdbc.update("""
                INSERT INTO reach_workload_observations (cluster, namespace, observed_at, source, reported_by)
                VALUES ('reused-prod', 'reused', now() - make_interval(hours => ?), 'CLUSTER_READER', 'test')
                """, hoursAgo);
        for (var w : workloads) {
            jdbc.update("""
                    INSERT INTO reach_workloads (cluster, namespace, kind, name, container, image, image_digest, ready_replicas)
                    VALUES ('reused-prod', 'reused', 'Deployment', ?, ?, ?, ?, 1)
                    """, w[0], w[0], "123.dkr.ecr.ap-northeast-1.amazonaws.com/" + w[1] + "@" + w[2], w[2]);
        }
    }

    /** 기준 범위만 지정한 필터 */
    private static ReachFindingFilter scope(Long scanId, Long target) {
        return new ReachFindingFilter(null, null, null, null, null, scanId, target);
    }

    private static long target(String digest) {
        return target(digest, "API");
    }

    /** 이미지 대상. 기본 범위는 app·대상 종류마다 하나라, 여러 대상을 같이 보려면 app을 나눈다 */
    private static long target(String digest, String app) {
        return jdbc.queryForObject("""
                INSERT INTO reach_targets (target_type, app, image_repository, image_digest, display_name)
                VALUES ('IMAGE', ?, 'reused-api', ?, 'api') RETURNING target_id
                """, Long.class, app, digest);
    }

    private static long repoTarget(String app, String commit) {
        return jdbc.queryForObject("""
                INSERT INTO reach_targets (target_type, app, repo_name, repo_commit, display_name)
                VALUES ('REPO', ?, 'service-backend', ?, 'repo') RETURNING target_id
                """, Long.class, app, commit);
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

    /** 그 스캔의 L3 실행 (V55). 근거 항목은 러너 run.json 이름 그대로 */
    private static void l3Run(long scanId) {
        jdbc.update("""
                INSERT INTO reach_l3_runs (scan_id, run_status, scenario, observation_method, observed_at, counts, detail)
                VALUES (?, 'SUCCEEDED', '2026-11-18.1', 'COVERAGE', now(), '{"REGION": 1}',
                        '{"build": {"imageDigest": "sha256:a"}, "configKeys": [{"name": "KAKAO_STUB", "enabled": true}],
                          "invocations": [{"segment": "001", "name": "categories", "request": "GET /api/v1/categories"},
                                          {"segment": "002", "name": "create", "request": "POST /items"}]}'::jsonb)
                """, scanId);
    }

    private static void l3Result(long findingId, long scanId, String reached, boolean regionsChecked, boolean startupOnly) {
        jdbc.update("""
                INSERT INTO reach_l3_results (finding_id, scan_id, reached, regions_checked, startup_only, detail)
                VALUES (?, ?, ?, ?, ?,
                        '{"during": ["002"], "note": "checked by hand",
                          "functions": [{"function": "org.example.Parser#check", "during": ["001", "002"]}],
                          "regions": [{"class": "org.example.Parser", "method": "check", "lines": [[626, 627]],
                                       "executedLines": [626, 627], "executed": true, "during": ["002"]}],
                          "paths": [{"target": "org.example.Parser#check", "reachedStep": 2, "of": 2}]}'::jsonb)
                """, findingId, scanId, reached, regionsChecked, startupOnly);
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
