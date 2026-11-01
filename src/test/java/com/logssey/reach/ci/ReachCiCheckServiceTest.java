package com.logssey.reach.ci;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ci.dto.ReachCiCheckResponse;

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

class ReachCiCheckServiceTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final String COMMIT = "bb4639b".repeat(5) + "00000";   // 40자
    private static final String DIGEST = "sha256:" + "a6ffffef".repeat(8);
    private static JdbcTemplate jdbc;
    private ReachCiCheckService service;

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
        jdbc.execute("TRUNCATE reach_ci_checks, reach_review_history, reach_reviews, reach_evidence, reach_verdicts, "
                + "reach_findings, reach_scans, reach_targets, dashboard_users RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO dashboard_users (login_id, password_hash, display_name, role) "
                + "VALUES ('admin', 'h', 'Admin', 'ADMIN')");
        service = new ReachCiCheckService(new ReachCiCheckRepository(JdbcClient.create(jdbc)));
    }

    @Test
    void requiresAdmin() {
        assertError(() -> service.create(null, "k", pr("GATE")), ErrorCode.UNAUTHENTICATED);
        assertError(() -> service.create("nobody", "k", pr("GATE")), ErrorCode.FORBIDDEN);
        assertError(() -> service.check(null, 1), ErrorCode.UNAUTHENTICATED);
    }

    @Test
    void pullRequestCheckCreatesAQueuedScanOnTheRepoTarget() {
        var created = service.create("admin", "service-backend-pr-123", pr("GATE"));
        assertThat(created.replayed()).isFalse();
        var check = created.check();
        assertThat(check.mode()).isEqualTo("PR");
        assertThat(check.scanStatus()).isEqualTo("QUEUED");
        assertThat(check.policy()).isEqualTo("GATE");

        // 레포 이름으로 app을 정하고(명세 3-2), 스캔은 PR 계기로 사용자가 요청한 것으로 남는다
        assertThat(jdbc.queryForMap("SELECT target_type, app, repo_name, repo_commit, display_name FROM reach_targets"))
                .containsEntry("target_type", "REPO").containsEntry("app", "API")
                .containsEntry("repo_commit", COMMIT).containsEntry("display_name", "service-backend @ bb4639b");
        assertThat(jdbc.queryForMap("SELECT scan_status, trigger_type, requested_by_kind, requested_by_user_id "
                + "FROM reach_scans WHERE scan_id = ?", check.scanId()))
                .containsEntry("scan_status", "QUEUED").containsEntry("trigger_type", "PR")
                .containsEntry("requested_by_kind", "USER").containsEntry("requested_by_user_id", 1L);

        var result = service.check("admin", check.id());
        assertThat(result.repository()).isEqualTo("service-backend");
        assertThat(result.headCommit()).isEqualTo(COMMIT);
        assertThat(result.pullRequest()).isEqualTo(new ReachCiCheckResponse.PullRequest(123, "main", "develop"));
        assertThat(result.baselineScanId()).isNull();
        assertThat(result.gate()).isNull();          // 아직 안 끝났다
        assertThat(result.findingsUrl()).isNull();
        assertError(() -> service.check("admin", 999), ErrorCode.NOT_FOUND);
    }

    @Test
    void sameKeyReplaysTheSameCheckAndADifferentBodyConflicts() {
        long first = service.create("admin", "k1", pr("GATE")).check().id();
        var again = service.create("admin", "k1", pr("GATE"));
        assertThat(again.replayed()).isTrue();
        assertThat(again.check().id()).isEqualTo(first);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM reach_scans", Long.class)).isEqualTo(1);

        assertError(() -> service.create("admin", "k1", pr("REPORT_ONLY")), ErrorCode.CONFLICT);
        assertError(() -> service.create("admin", null, pr("GATE")), ErrorCode.INVALID_INPUT);
        assertError(() -> service.create("admin", " ", pr("GATE")), ErrorCode.INVALID_INPUT);
        assertError(() -> service.create("admin", "k".repeat(65), pr("GATE")), ErrorCode.INVALID_INPUT);
        assertThat(service.create("admin", "k".repeat(64), pr("GATE")).replayed()).isFalse();
    }

    @Test
    void sameImageReusesItsTargetAndAppComesFromTheRepositoryName() {
        long a = scanTarget(service.create("admin", "a", image("IMAGE_BUILD", "logssey/reused-chat", DIGEST)).check().scanId());
        long b = scanTarget(service.create("admin", "b", image("IMAGE_BUILD", "logssey/reused-chat", DIGEST.toUpperCase()
                .replace("SHA256", "sha256"))).check().scanId());
        assertThat(a).isEqualTo(b);
        assertThat(jdbc.queryForMap("SELECT app, display_name FROM reach_targets WHERE target_id = ?", a))
                .containsEntry("app", "CHAT").containsEntry("display_name", "reused-chat @ a6ffffef");

        // 같은 커밋이라도 하위 경로가 다르면 다른 대상이다. service-backend/chat-server는 CHAT
        var chat = new ReachTargetRequest("REPO", null, new ReachTargetRequest.Repo("service-backend", COMMIT, "chat-server"), null);
        long c = scanTarget(service.create("admin", "c", request("MANUAL", chat, null, null)).check().scanId());
        long d = scanTarget(service.create("admin", "d", request("MANUAL", repo(COMMIT), null, null)).check().scanId());
        assertThat(c).isNotEqualTo(d);
        assertThat(jdbc.queryForObject("SELECT app FROM reach_targets WHERE target_id = ?", String.class, c)).isEqualTo("CHAT");

        // 이미 API로 등록된 이미지를 다른 app으로 요청하면 어느 서비스인지 모른다
        var wrongApp = new ReachTargetRequest("IMAGE", "WEB", null, new ReachTargetRequest.Image("logssey/reused-chat", DIGEST));
        assertError(() -> service.create("admin", "e", request("IMAGE_BUILD", wrongApp, null, null)), ErrorCode.UNPROCESSABLE);
    }

    @Test
    void rejectsBodiesThatDoNotFitTheMode() {
        var badDigest = image("IMAGE_BUILD", "logssey/reused-api", "sha256:abc");
        var tagged = image("IMAGE_BUILD", "logssey/reused-api:latest", DIGEST);
        var unknownImage = image("IMAGE_BUILD", "logssey/other", DIGEST);
        var prOnImage = new ReachCiCheckRequest("PR", "service-backend", COMMIT, null,
                new ReachTargetRequest("IMAGE", null, null, new ReachTargetRequest.Image("logssey/reused-api", DIGEST)),
                null, null, null);
        var prOtherCommit = new ReachCiCheckRequest("PR", "service-backend", "c".repeat(40), null, repo(COMMIT),
                null, null, null);
        var buildOnRepo = request("IMAGE_BUILD", repo(COMMIT), null, null);
        var both = request("SCHEDULE", repo(COMMIT), 1L, null);
        var neither = request("SCHEDULE", null, null, null);
        var rescanInPr = new ReachCiCheckRequest("PR", "service-backend", COMMIT, null, null, 1L, null, null);
        var badMode = request("NIGHTLY", repo(COMMIT), null, null);
        var badPolicy = new ReachCiCheckRequest("MANUAL", "service-backend", null, null, repo(COMMIT), null, "BLOCK", null);
        var badPr = new ReachCiCheckRequest("MANUAL", "service-backend", null,
                new ReachCiCheckRequest.PullRequest(0, "main", "x"), repo(COMMIT), null, null, null);
        var noRepository = new ReachCiCheckRequest("MANUAL", null, null, null, repo(COMMIT), null, null, null);

        for (var body : new ReachCiCheckRequest[] {badDigest, tagged, prOnImage, prOtherCommit, buildOnRepo, both,
                neither, rescanInPr, badMode, badPolicy, badPr, noRepository, null}) {
            assertError(() -> service.create("admin", "k", body), ErrorCode.INVALID_INPUT);
        }
        assertError(() -> service.create("admin", "k", unknownImage), ErrorCode.UNPROCESSABLE);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM reach_ci_checks", Long.class)).isZero();
    }

    @Test
    void rescanUsesTheTargetOfASucceededScanAndBaselineMustHaveSucceeded() {
        long target = imageTarget();
        long done = scan(target, "SUCCEEDED");
        long running = scan(target, "RUNNING");

        var rescan = service.create("admin", "r", request("SCHEDULE", null, done, null)).check();
        assertThat(scanTarget(rescan.scanId())).isEqualTo(target);
        assertThat(jdbc.queryForObject("SELECT rescan_of_scan_id FROM reach_scans WHERE scan_id = ?", Long.class,
                rescan.scanId())).isEqualTo(done);

        assertError(() -> service.create("admin", "r2", request("SCHEDULE", null, running, null)), ErrorCode.UNPROCESSABLE);
        assertError(() -> service.create("admin", "r3", request("SCHEDULE", null, 999L, null)), ErrorCode.UNPROCESSABLE);
        assertError(() -> service.create("admin", "b1", request("MANUAL", repo(COMMIT), null, running)), ErrorCode.INVALID_INPUT);
        assertThat(service.check("admin", service.create("admin", "b2", request("MANUAL", repo(COMMIT), null, done))
                .check().id()).baselineScanId()).isEqualTo(done);
    }

    @Test
    void gateCountsOnlyFindingsMissingFromTheBaselineAndWarns() {
        // 기준 스캔(main)은 다른 대상이다. 같은 purl × CVE는 새 것이 아니다
        long baseline = scan(imageTarget(), "SUCCEEDED");
        finding(baseline, "a", "CRITICAL", "REACHABLE");

        long checkId = service.create("admin", "k", request("MANUAL", repo(COMMIT), null, baseline, "GATE")).check().id();
        long scanId = service.check("admin", checkId).scanId();
        finding(scanId, "a", "CRITICAL", "REACHABLE");      // 기준에 있다 → 새 것 아님
        finding(scanId, "b", "MEDIUM", "REACHABLE");        // REACHABLE_OTHER
        finding(scanId, "c", "LOW", "UNKNOWN");             // UNKNOWN_ANY
        finding(scanId, "d", "HIGH", "NOT_ANALYZED");       // NOT_ANALYZED_CRITICAL_HIGH
        finding(scanId, "e", "LOW", "NOT_ANALYZED");        // 통과
        finding(scanId, "f", "CRITICAL", "UNREACHABLE");    // 통과
        finish(scanId, "SUCCEEDED");

        var result = service.check("admin", checkId);
        var gate = result.gate();
        assertThat(gate.result()).isEqualTo("WARN");
        assertThat(gate.exitCode()).isZero();
        assertThat(gate.reasons()).extracting(ReachCiCheckResponse.Reason::condition)
                .containsExactly("REACHABLE_OTHER", "UNKNOWN_ANY", "NOT_ANALYZED_CRITICAL_HIGH");
        assertThat(gate.reasons().get(2).summary()).isEqualTo("새 Finding 중 NOT_ANALYZED인 CRITICAL·HIGH 1건");
        assertThat(gate.newFindings().total()).isEqualTo(5);
        assertThat(gate.newFindings().byStatus()).containsExactly(entry("REACHABLE", 1L), entry("UNKNOWN", 1L),
                entry("UNREACHABLE", 1L), entry("NOT_ANALYZED", 2L));
        assertThat(result.findingsUrl()).isEqualTo("/api/v1/reach/findings?scanId=" + scanId);
        assertThat(result.finishedAt()).isNotNull();
    }

    @Test
    void newReachableHighFailsTheGateButReportOnlyAlwaysPasses() {
        long gateCheck = service.create("admin", "g", request("MANUAL", repo(COMMIT), null, null, "GATE")).check().id();
        long reportCheck = service.create("admin", "r", request("MANUAL", repo("d".repeat(40)), null, null, null)).check().id();
        for (long checkId : new long[] {gateCheck, reportCheck}) {
            long scanId = service.check("admin", checkId).scanId();
            finding(scanId, "a", "HIGH", "REACHABLE");
            finding(scanId, "b", "LOW", "UNKNOWN");
            finish(scanId, "SUCCEEDED");
        }

        var gate = service.check("admin", gateCheck).gate();
        assertThat(gate.result()).isEqualTo("FAIL");
        assertThat(gate.exitCode()).isEqualTo(1);

        // 리포트 전용은 늘 PASS지만 걸린 조건은 남긴다 (명세에 없어 정한 것)
        var report = service.check("admin", reportCheck);
        assertThat(report.policy()).isEqualTo("REPORT_ONLY");
        assertThat(report.gate().result()).isEqualTo("PASS");
        assertThat(report.gate().exitCode()).isZero();
        assertThat(report.gate().reasons()).extracting(ReachCiCheckResponse.Reason::condition)
                .containsExactly("REACHABLE_CRITICAL_HIGH", "UNKNOWN_ANY");
    }

    @Test
    void failedScanHasNoGate() {
        long checkId = service.create("admin", "k", pr("GATE")).check().id();
        finish(service.check("admin", checkId).scanId(), "FAILED");
        var result = service.check("admin", checkId);
        assertThat(result.scanStatus()).isEqualTo("FAILED");
        assertThat(result.gate()).isNull();
        assertThat(result.finishedAt()).isNotNull();
    }

    private static ReachCiCheckRequest pr(String policy) {
        return new ReachCiCheckRequest("PR", "service-backend", COMMIT,
                new ReachCiCheckRequest.PullRequest(123, "main", "develop"), repo(COMMIT), null, policy, null);
    }

    private static ReachCiCheckRequest image(String mode, String repository, String digest) {
        return new ReachCiCheckRequest(mode, "service-backend", null, null,
                new ReachTargetRequest("IMAGE", null, null, new ReachTargetRequest.Image(repository, digest)),
                null, null, null);
    }

    private static ReachCiCheckRequest request(String mode, ReachTargetRequest target, Long rescanOf, Long baseline) {
        return request(mode, target, rescanOf, baseline, null);
    }

    private static ReachCiCheckRequest request(String mode, ReachTargetRequest target, Long rescanOf, Long baseline,
                                               String policy) {
        return new ReachCiCheckRequest(mode, "service-backend", null, null, target, rescanOf, policy, baseline);
    }

    private static ReachTargetRequest repo(String commit) {
        return new ReachTargetRequest("REPO", null, new ReachTargetRequest.Repo("service-backend", commit, null), null);
    }

    private static long scanTarget(long scanId) {
        return jdbc.queryForObject("SELECT target_id FROM reach_scans WHERE scan_id = ?", Long.class, scanId);
    }

    private static long imageTarget() {
        return jdbc.queryForObject("""
                INSERT INTO reach_targets (target_type, app, image_repository, image_digest, display_name)
                VALUES ('IMAGE', 'API', 'logssey/reused-api', 'sha256:main', 'main') RETURNING target_id
                """, Long.class);
    }

    private static long scan(long targetId, String status) {
        long id = jdbc.queryForObject("""
                INSERT INTO reach_scans (target_id, trigger_type, requested_by_kind)
                VALUES (?, 'MANUAL', 'SYSTEM') RETURNING scan_id
                """, Long.class, targetId);
        if (!status.equals("QUEUED")) finish(id, status);
        return id;
    }

    /** 상태에 맞게 시각과 실패 사유를 채운다 (V34 CHECK: 끝난 스캔만 finished_at, FAILED는 failure_code) */
    private static void finish(long scanId, String status) {
        boolean done = status.equals("SUCCEEDED") || status.equals("FAILED");
        jdbc.update("""
                UPDATE reach_scans SET scan_status = ?, started_at = now(),
                       finished_at = CASE WHEN ? THEN now() END, failure_code = ?
                WHERE scan_id = ?
                """, status, done, status.equals("FAILED") ? "ANALYSIS_FAILED" : null, scanId);
    }

    /** 스캔 대상의 Finding + 그 스캔의 도구 판정 + 검토 전 검토 한 벌. purl은 component로 정한다 */
    private static void finding(long scanId, String component, String severity, String status) {
        long id = jdbc.queryForObject("""
                INSERT INTO reach_findings (target_id, purl, component_name, component_version, ecosystem,
                                            vulnerability_id, severity, sources, last_scan_id, first_seen_at, last_seen_at)
                SELECT target_id, 'pkg:maven/test/' || ? || '@1', ?, '1', 'maven', 'CVE-2026-1', ?, ARRAY['TRIVY'],
                       scan_id, now(), now()
                FROM reach_scans WHERE scan_id = ? RETURNING finding_id
                """, Long.class, component, component, severity, scanId);
        boolean notAnalyzed = status.equals("NOT_ANALYZED");
        jdbc.update("""
                INSERT INTO reach_verdicts (finding_id, scan_id, status, method, not_analyzed_reason, summary,
                                            engine, evidence_hash, is_current, analyzed_at)
                VALUES (?, ?, ?, ?, ?, 'test', '{}', 'h', true, now())
                """, id, scanId, status, notAnalyzed ? null : "CALLGRAPH", notAnalyzed ? "OS_PACKAGE" : null);
        jdbc.update("INSERT INTO reach_reviews (finding_id) VALUES (?)", id);
    }

    private static void assertError(Runnable call, ErrorCode code) {
        assertThatThrownBy(call::run).isInstanceOfSatisfying(ApiException.class,
                e -> assertThat(e.errorCode()).isEqualTo(code));
    }
}
