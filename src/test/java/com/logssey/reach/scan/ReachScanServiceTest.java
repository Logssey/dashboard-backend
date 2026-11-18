package com.logssey.reach.scan;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.scan.dto.ReachScanPageResponse;
import com.logssey.reach.scan.dto.ReachScanResponse;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

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
    private static final ReachScanFilter ALL = new ReachScanFilter(null, null, null, null, null, null);
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
    void scanShowsItsL3RunOnlyWhenTheAppWasRun() {
        long target = target("sha256:a");
        long observed = scan(target, "SUCCEEDED");
        long failedRun = scan(target, "SUCCEEDED");
        long rescan = scan(target, "SUCCEEDED", "SCHEDULE", 0);
        jdbc.update("""
                INSERT INTO reach_l3_runs (scan_id, run_status, scenario, observation_method, observed_at, counts)
                VALUES (?, 'SUCCEEDED', '2026-11-18.1', 'COVERAGE', now(), '{"REGION": 1, "FUNCTION": 2, "NONE": 11, "NOT_RECORDED": 0}')
                """, observed);
        jdbc.update("INSERT INTO reach_l3_runs (scan_id, run_status, error) VALUES (?, 'FAILED', 'L3 run failed on the runner')",
                failedRun);

        var l3 = service.scan("admin", observed).l3();
        assertThat(l3.runStatus()).isEqualTo("SUCCEEDED");
        assertThat(l3.scenario()).isEqualTo("2026-11-18.1");
        assertThat(l3.observedAt()).isNotNull();
        assertThat(l3.counts().get("FUNCTION").asInt()).isEqualTo(2);
        // L3가 실패해도 스캔은 SUCCEEDED다
        var failed = service.scan("admin", failedRun);
        assertThat(failed.scanStatus()).isEqualTo("SUCCEEDED");
        assertThat(failed.l3().runStatus()).isEqualTo("FAILED");
        assertThat(failed.l3().error()).isEqualTo("L3 run failed on the runner");
        assertThat(failed.counts()).isNotNull();
        // 재대조는 앱을 띄우지 않는다
        assertThat(service.scan("admin", rescan).l3()).isNull();
        // 목록에서도 같다
        var listed = service.scans("admin", ALL, null, null, null).items();
        assertThat(listed.stream().filter(i -> i.l3() != null).map(i -> i.id())).containsExactlyInAnyOrder(observed, failedRun);
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

    // ---- API-02 스캔 이력 ----

    @Test
    void listRequiresAdmin() {
        assertError(() -> service.scans(null, ALL, null, null, null), ErrorCode.UNAUTHENTICATED);
        assertError(() -> service.scans("nobody", ALL, null, null, null), ErrorCode.FORBIDDEN);
    }

    @Test
    void listsNewestFirstByDefault() {
        long target = target("sha256:a");
        long old = scan(target, "SUCCEEDED", "MANUAL", 30);
        long middle = scan(target, "FAILED", "PR", 20);
        long recent = scan(target, "RUNNING", "SCHEDULE", 10);

        assertThat(ids(list(ALL))).containsExactly(recent, middle, old);
        assertThat(ids(list(sorted("createdAt")))).containsExactly(old, middle, recent);
    }

    @Test
    void finishedAtSortPutsUnfinishedScansFirstWhenDescending() {
        long target = target("sha256:a");
        long slow = scan(target, "SUCCEEDED", "MANUAL", 30);
        long quick = scan(target, "SUCCEEDED", "MANUAL", 20);
        long running = scan(target, "RUNNING", "MANUAL", 10);
        // 가장 먼저 시작했지만 가장 늦게 끝난 스캔: 만든 순서와 끝난 순서가 달라진다
        jdbc.update("UPDATE reach_scans SET finished_at = now() WHERE scan_id = ?", slow);

        assertThat(ids(list(sorted("-finishedAt")))).containsExactly(running, slow, quick);
        assertThat(ids(list(sorted("finishedAt")))).containsExactly(quick, slow, running);
    }

    @Test
    void filtersByTargetStatusAndTrigger() {
        long a = target("sha256:a");
        long b = target("sha256:b");
        long succeeded = scan(a, "SUCCEEDED", "MANUAL", 30);
        long failed = scan(a, "FAILED", "PR", 20);
        long running = scan(a, "RUNNING", "PR", 10);
        long other = scan(b, "SUCCEEDED", "PR", 5);

        assertThat(ids(list(new ReachScanFilter(a, null, null, null, null, null))))
                .containsExactly(running, failed, succeeded);
        assertThat(ids(list(new ReachScanFilter(null, List.of("SUCCEEDED", "FAILED"), null, null, null, null))))
                .containsExactly(other, failed, succeeded);
        assertThat(ids(list(new ReachScanFilter(a, List.of("SUCCEEDED", "FAILED"), List.of("PR"), null, null, null))))
                .containsExactly(failed);
        // 스캔이 없는 대상은 빈 목록, 없는 대상은 404
        long noScans = target("sha256:c");
        assertThat(list(new ReachScanFilter(noScans, null, null, null, null, null)).items()).isEmpty();
        assertError(() -> list(new ReachScanFilter(999L, null, null, null, null, null)), ErrorCode.NOT_FOUND);
    }

    @Test
    void createdAtRangeIncludesFromAndExcludesTo() {
        long target = target("sha256:a");
        long start = scan(target, "SUCCEEDED");
        long noon = scan(target, "SUCCEEDED");
        long nextDay = scan(target, "SUCCEEDED");
        createdAt(start, "2026-10-01T00:00:00Z");
        createdAt(noon, "2026-10-01T12:00:00Z");
        createdAt(nextDay, "2026-10-02T00:00:00Z");

        var oneDay = new ReachScanFilter(null, null, null,
                Instant.parse("2026-10-01T00:00:00Z"), Instant.parse("2026-10-02T00:00:00Z"), null);
        assertThat(ids(list(oneDay))).containsExactly(noon, start);
    }

    @Test
    void cursorVisitsEveryScanOnceInEachSort() {
        long target = target("sha256:a");
        var newestFirst = new ArrayList<Long>();
        for (int i = 1; i <= 5; i++) newestFirst.add(scan(target, i == 3 ? "RUNNING" : "SUCCEEDED", "MANUAL", i * 10));
        long running = newestFirst.get(2);
        // 끝난 시각 내림차순: 안 끝난 스캔이 맨 위, 나머지는 만든 순서와 같다
        var finishedDesc = new ArrayList<Long>(newestFirst);
        finishedDesc.remove(running);
        finishedDesc.add(0, running);

        var expected = Map.of(
                "-createdAt", newestFirst,
                "createdAt", newestFirst.reversed(),
                "-finishedAt", finishedDesc,
                "finishedAt", finishedDesc.reversed());
        expected.forEach((sort, ids) -> {
            var seen = new ArrayList<Long>();
            String cursor = null;
            do {
                var page = service.scans("admin", sorted(sort), 2, cursor, "total");
                assertThat(page.totalCount()).isEqualTo(5);
                seen.addAll(ids(page));
                cursor = page.nextCursor();
            } while (cursor != null);
            assertThat(seen).as(sort).containsExactlyElementsOf(ids);
        });
    }

    @Test
    void cursorCannotBeReusedWithAnotherFilterOrSort() {
        long target = target("sha256:a");
        for (int i = 1; i <= 3; i++) scan(target, "SUCCEEDED", "MANUAL", i * 10);
        String cursor = service.scans("admin", ALL, 1, null, null).nextCursor();

        assertError(() -> service.scans("admin", sorted("createdAt"), 1, cursor, null), ErrorCode.INVALID_INPUT);
        var other = new ReachScanFilter(null, List.of("SUCCEEDED"), null, null, null, null);
        assertError(() -> service.scans("admin", other, 1, cursor, null), ErrorCode.INVALID_INPUT);
    }

    @Test
    void listRejectsValuesOutsideTheSpec() {
        assertError(() -> new ReachScanFilter(null, List.of("DONE"), null, null, null, null), ErrorCode.INVALID_INPUT);
        assertError(() -> new ReachScanFilter(null, null, List.of("PUSH"), null, null, null), ErrorCode.INVALID_INPUT);
        assertError(() -> sorted("name"), ErrorCode.INVALID_INPUT);
        assertError(() -> new ReachScanFilter(null, null, null,
                Instant.parse("2026-10-02T00:00:00Z"), Instant.parse("2026-10-01T00:00:00Z"), null), ErrorCode.INVALID_INPUT);
        assertError(() -> service.scans("admin", ALL, 101, null, null), ErrorCode.INVALID_INPUT);
        assertError(() -> service.scans("admin", ALL, 0, null, null), ErrorCode.INVALID_INPUT);
        assertError(() -> service.scans("admin", ALL, null, "not-a-cursor", null), ErrorCode.INVALID_INPUT);
        assertError(() -> service.scans("admin", ALL, null, null, "matrix"), ErrorCode.INVALID_INPUT);
    }

    @Test
    void listItemsMatchTheDetailAndOnlySucceededScansHaveCounts() {
        long target = target("sha256:a");
        long succeeded = scan(target, "SUCCEEDED", "MANUAL", 30);
        long running = scan(target, "RUNNING", "MANUAL", 20);
        long empty = scan(target, "SUCCEEDED", "MANUAL", 10);
        finding(succeeded, "a", "HIGH", "UNREACHABLE", "CONFIRMED");
        finding(succeeded, "b", "LOW", "NOT_ANALYZED", "UNREVIEWED");
        jdbc.update("UPDATE reach_scans SET stages = '[{\"name\": \"SBOM\", \"status\": \"SUCCEEDED\"}]' WHERE scan_id = ?",
                succeeded);

        // 목록 항목은 상세(API-03)와 같다. stages·tools·counts까지
        var items = list(ALL).items();
        assertThat(items).containsExactly(
                service.scan("admin", empty), service.scan("admin", running), service.scan("admin", succeeded));
        assertThat(items.get(2).counts().total()).isEqualTo(2);
        assertThat(items.get(1).counts()).isNull();
        assertThat(items.get(0).counts().total()).isZero();
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

    private static long scan(long targetId, String status) {
        return scan(targetId, status, "MANUAL", 0);
    }

    /**
     * minutesAgo 분 전에 만든 스캔. 시작은 만든 때, 끝난 스캔은 만든 지 1분 뒤에 끝난 것으로 둔다.
     * 상태에 맞게 시각과 실패 사유를 채운다 (V34 CHECK: 끝난 스캔만 finished_at, FAILED는 failure_code).
     * now()는 한 문장 안에서 같은 값이라 세 번 써도 같은 시각이다
     */
    private static long scan(long targetId, String status, String trigger, int minutesAgo) {
        boolean failed = status.equals("FAILED");
        return jdbc.queryForObject("""
                INSERT INTO reach_scans (target_id, scan_status, trigger_type, requested_by_kind, created_at, started_at,
                                         finished_at, failure_code, failure_stage, failure_message)
                VALUES (?, ?, ?, 'SYSTEM',
                        now() - make_interval(mins => ?),
                        CASE WHEN ? <> 'QUEUED' THEN now() - make_interval(mins => ?) END,
                        CASE WHEN ? IN ('SUCCEEDED', 'FAILED') THEN now() - make_interval(mins => ?) + interval '1 minute' END,
                        ?, ?, ?)
                RETURNING scan_id
                """, Long.class, targetId, status, trigger, minutesAgo, status, minutesAgo, status, minutesAgo,
                failed ? "E-L2-01" : null, failed ? "L2" : null, failed ? "call graph timed out" : null);
    }

    private static void createdAt(long scanId, String at) {
        jdbc.update("UPDATE reach_scans SET created_at = ?::timestamptz WHERE scan_id = ?", at, scanId);
    }

    private static ReachScanFilter sorted(String sort) {
        return new ReachScanFilter(null, null, null, null, null, sort);
    }

    private ReachScanPageResponse list(ReachScanFilter filter) {
        return service.scans("admin", filter, null, null, null);
    }

    private static List<Long> ids(ReachScanPageResponse page) {
        return page.items().stream().map(ReachScanResponse::id).toList();
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
