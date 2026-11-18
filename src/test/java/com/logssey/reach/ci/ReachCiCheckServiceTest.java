package com.logssey.reach.ci;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.ci.dto.ReachCiCheckResponse;
import com.logssey.reach.scan.ReachScanRepository;
import com.logssey.reach.scan.ReachScanService;
import com.logssey.reach.scan.dto.ReachScanResponse;
import com.logssey.reach.ReachProperties;
import com.logssey.reach.ReachTestProperties;

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
        service = new ReachCiCheckService(new ReachCiCheckRepository(JdbcClient.create(jdbc)), ReachTestProperties.REUSED);
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
    void appsComeFromTheConfigurationNotFromReUsedNames() {
        // Re:Used가 아닌 서비스의 설정이면 그 서비스의 레포·이미지로 app을 정하고, Re:Used 이름은 모른다 (PRD FR-15)
        var other = new ReachProperties(List.of(
                new ReachProperties.App("ORDER", "acme/order-service", null, "acme/order"),
                new ReachProperties.App("BATCH", "order-service", "batch", null)), null);
        service = new ReachCiCheckService(new ReachCiCheckRepository(JdbcClient.create(jdbc)), other);
        String digest = "sha256:" + "c".repeat(64);

        service.create("admin", "o1", request("MANUAL", repoOf("order-service", null), null, null));
        service.create("admin", "o2", request("MANUAL", repoOf("acme/order-service", "batch"), null, null));
        service.create("admin", "o3", request("MANUAL", repoOf("order-service", "docs"), null, null));   // 경로 없는 등록으로
        service.create("admin", "o4", image("IMAGE_BUILD", "acme/order", digest));
        assertThat(jdbc.queryForList("SELECT app FROM reach_targets ORDER BY target_id", String.class))
                .containsExactly("ORDER", "BATCH", "ORDER", "ORDER");

        assertError(() -> service.create("admin", "o5", request("MANUAL", repo(COMMIT), null, null)), ErrorCode.UNPROCESSABLE);
        assertError(() -> service.create("admin", "o6", image("IMAGE_BUILD", "logssey/reused-api", digest)),
                ErrorCode.UNPROCESSABLE);
        var reusedApp = new ReachTargetRequest("REPO", "API", new ReachTargetRequest.Repo("order-service", COMMIT, null), null);
        assertError(() -> service.create("admin", "o7", request("MANUAL", reusedApp, null, null)), ErrorCode.INVALID_INPUT);
    }

    @Test
    void withoutConfiguredAppsNoTargetCanBeResolved() {
        service = new ReachCiCheckService(new ReachCiCheckRepository(JdbcClient.create(jdbc)), new ReachProperties(null, null));
        assertError(() -> service.create("admin", "k", pr("GATE")), ErrorCode.UNPROCESSABLE);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM reach_targets", Long.class)).isZero();
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

    @Test
    void scanRequestOnAnImageCreatesAManualCheckWithDefaultOptions() {
        var image = new ReachTargetRequest("IMAGE", "API", null, new ReachTargetRequest.Image("logssey/reused-api", DIGEST));
        var created = service.createScan("admin", "s1", new ReachScanRequest(image, null, null));
        assertThat(created.replayed()).isFalse();
        long scanId = created.check().scanId();

        // 이미지 대상은 설정에서 그 이미지 앱의 레포를 남긴다(러너를 띄울 레포). options를 빼면 기본값을 남긴다 (명세 API-01)
        assertThat(jdbc.queryForMap("SELECT mode, repository, head_commit, policy, options::text AS options "
                + "FROM reach_ci_checks WHERE scan_id = ?", scanId))
                .containsEntry("mode", "MANUAL").containsEntry("repository", "service-backend").containsEntry("head_commit", null)
                .containsEntry("policy", "REPORT_ONLY")
                .containsEntry("options", "{\"l1\": true, \"l2\": true, \"crossCheck\": [\"GRYPE\"]}");

        // 응답은 API-03과 같은 Scan이다
        var scan = new ReachScanService(new ReachScanRepository(JdbcClient.create(jdbc))).scan("admin", scanId);
        assertThat(scan.scanStatus()).isEqualTo("QUEUED");
        assertThat(scan.trigger()).isEqualTo("MANUAL");
        assertThat(scan.target().displayName()).isEqualTo("reused-api @ a6ffffef");
        assertThat(scan.requestedBy()).isEqualTo(new ReachScanResponse.RequestedBy("USER", 1L, null, null));
        assertThat(scan.counts()).isNull();
    }

    @Test
    void scanRequestOnARepoKeepsTheCommitAndOptions() {
        var options = new ReachScanRequest.Options(List.of(), true, false);
        long scanId = service.createScan("admin", "s1", new ReachScanRequest(repo(COMMIT.toUpperCase()), null, options))
                .check().scanId();
        assertThat(jdbc.queryForMap("SELECT repository, head_commit, options->'l2' AS l2, "
                + "jsonb_array_length(options->'crossCheck') AS cross FROM reach_ci_checks WHERE scan_id = ?", scanId))
                .containsEntry("repository", "service-backend").containsEntry("head_commit", COMMIT)
                .containsEntry("cross", 0);
        assertThat(jdbc.queryForObject("SELECT options->>'l2' FROM reach_ci_checks WHERE scan_id = ?", String.class, scanId))
                .isEqualTo("false");
    }

    @Test
    void scanRequestValidatesTheBodyAndSharesIdempotencyWithCiChecks() {
        long done = scan(imageTarget(), "SUCCEEDED");
        var both = new ReachScanRequest(repo(COMMIT), done, null);
        var neither = new ReachScanRequest(null, null, null);
        var trivy = new ReachScanRequest(repo(COMMIT), null, new ReachScanRequest.Options(List.of("TRIVY"), null, null));
        for (var body : new ReachScanRequest[] {both, neither, trivy, null}) {
            assertError(() -> service.createScan("admin", "k", body), ErrorCode.INVALID_INPUT);
        }
        assertError(() -> service.createScan("admin", null, new ReachScanRequest(repo(COMMIT), null, null)),
                ErrorCode.INVALID_INPUT);
        assertError(() -> service.createScan(null, "k", new ReachScanRequest(repo(COMMIT), null, null)),
                ErrorCode.UNAUTHENTICATED);

        // 재대조는 원래 스캔의 대상을 쓴다. 같은 키로 다시 보내면 같은 스캔
        var rescan = new ReachScanRequest(null, done, null);
        long scanId = service.createScan("admin", "r", rescan).check().scanId();
        assertThat(scanTarget(scanId)).isEqualTo(scanTarget(done));
        var again = service.createScan("admin", "r", rescan);
        assertThat(again.replayed()).isTrue();
        assertThat(again.check().scanId()).isEqualTo(scanId);

        // 키는 호출 주체마다 하나라 API-12에서 쓴 키를 API-01에 쓰면 본문이 달라 409
        service.create("admin", "shared", pr("GATE"));
        assertError(() -> service.createScan("admin", "shared", rescan), ErrorCode.CONFLICT);
    }

    @Test
    void scanRequestDispatchesTheRunnerOfTheTargetRepository() {
        var dispatcher = new RecordingDispatcher();
        var apps = new ReachProperties(List.of(
                new ReachProperties.App("API", "Logssey/service-backend", null, "logssey/reused-api"),
                new ReachProperties.App("CHAT", "service-backend", "chat-server", "logssey/reused-chat"),
                new ReachProperties.App("EXT", null, null, "vendor/ext")), null);
        service = new ReachCiCheckService(new ReachCiCheckRepository(JdbcClient.create(jdbc)), apps, dispatcher);

        // 레포 대상: 요청한 레포의 워크플로, 커밋과 하위 경로. 소유자를 붙인 설정이어도 레포 이름만 보낸다
        var repo = new ReachTargetRequest("REPO", null, new ReachTargetRequest.Repo("service-backend", COMMIT, "chat-server"), null);
        long repoCheck = service.createScan("admin", "d1", new ReachScanRequest(repo, null, null)).check().id();
        // 이미지 대상: 그 이미지 앱의 레포, 앱의 하위 경로
        var image = new ReachTargetRequest("IMAGE", null, null, new ReachTargetRequest.Image("logssey/reused-chat", DIGEST));
        long imageCheck = service.createScan("admin", "d2", new ReachScanRequest(image, null, null)).check().id();
        assertThat(dispatcher.calls).containsExactly(
                new Call("service-backend", Map.of("check_id", Long.toString(repoCheck), "target_type", "REPO",
                        "commit", COMMIT, "path", "chat-server", "image_repository", "", "image_digest", "")),
                new Call("service-backend", Map.of("check_id", Long.toString(imageCheck), "target_type", "IMAGE",
                        "commit", "", "path", "chat-server", "image_repository", "logssey/reused-chat",
                        "image_digest", DIGEST)));

        // 같은 키로 다시 보내면 띄우지 않는다
        dispatcher.calls.clear();
        service.createScan("admin", "d1", new ReachScanRequest(repo, null, null));
        assertThat(dispatcher.calls).isEmpty();

        // 재대조는 원래 스캔의 대상으로 띄우고 rescan_of를 더한다(러너가 보관한 SBOM으로 대조)
        long done = scan(scanTarget(imageCheckScan(imageCheck)), "SUCCEEDED");
        long rescan = service.createScan("admin", "d4", new ReachScanRequest(null, done, null)).check().id();
        assertThat(dispatcher.calls).containsExactly(
                new Call("service-backend", Map.of("check_id", Long.toString(rescan), "target_type", "IMAGE",
                        "commit", "", "path", "chat-server", "image_repository", "logssey/reused-chat",
                        "image_digest", DIGEST, "rescan_of", Long.toString(done))));
        assertThat(jdbc.queryForObject("SELECT repository FROM reach_ci_checks WHERE check_id = ?", String.class, rescan))
                .isEqualTo("service-backend");
        dispatcher.calls.clear();

        // 레포가 없는 이미지 앱은 띄울 워크플로가 없다 → 422 (트랜잭션은 Spring이 되돌린다. 통합 테스트에서 본다)
        var ext = new ReachTargetRequest("IMAGE", null, null, new ReachTargetRequest.Image("vendor/ext", DIGEST));
        assertError(() -> service.createScan("admin", "d5", new ReachScanRequest(ext, null, null)), ErrorCode.UNPROCESSABLE);
        assertThat(dispatcher.calls).isEmpty();

        // 띄우는 설정이 없으면 지금처럼 QUEUED로 남는다(레포 없는 이미지 앱도 받는다)
        dispatcher.enabled = false;
        service.createScan("admin", "d6", new ReachScanRequest(ext, null, null));
        assertThat(dispatcher.calls).isEmpty();
    }

    @Test
    void scanRequestDispatchesNpmAppsToo() {
        var dispatcher = new RecordingDispatcher();
        service = new ReachCiCheckService(new ReachCiCheckRepository(JdbcClient.create(jdbc)),
                ReachTestProperties.REUSED, dispatcher);   // WEB·CHAT은 npm

        // npm 앱도 띄운다. 러너가 앱 jar가 없으면 L2만 건너뛰고 SBOM·CVE 대조로 올린다(reach-scan.sh, bundle.py --no-l2)
        var chatImage = new ReachTargetRequest("IMAGE", null, null, new ReachTargetRequest.Image("logssey/reused-chat", DIGEST));
        long check = service.createScan("admin", "n1", new ReachScanRequest(chatImage, null, null)).check().id();
        assertThat(dispatcher.calls).containsExactly(new Call("service-backend", Map.of("check_id", Long.toString(check),
                "target_type", "IMAGE", "commit", "", "path", "chat-server", "image_repository", "logssey/reused-chat",
                "image_digest", DIGEST)));
    }

    @Test
    void dailyRescanCreatesASystemScheduleCheckOncePerDayAndDispatchesIt() {
        var dispatcher = new RecordingDispatcher();
        service = new ReachCiCheckService(new ReachCiCheckRepository(JdbcClient.create(jdbc)),
                ReachTestProperties.REUSED, dispatcher);
        long target = imageTarget();
        long done = scan(target, "SUCCEEDED");
        var day = java.time.LocalDate.of(2026, 11, 18);

        var created = service.createRescan(done, day).orElseThrow();
        assertThat(created.replayed()).isFalse();
        var check = service.check("admin", created.check().id());
        assertThat(check.mode()).isEqualTo("SCHEDULE");
        assertThat(check.repository()).isEqualTo("service-backend");
        assertThat(scanTarget(check.scanId())).isEqualTo(target);
        assertThat(jdbc.queryForMap("SELECT trigger_type, rescan_of_scan_id, requested_by_kind FROM reach_scans "
                + "WHERE scan_id = ?", check.scanId()))
                .containsEntry("trigger_type", "SCHEDULE").containsEntry("rescan_of_scan_id", done)
                .containsEntry("requested_by_kind", "SYSTEM");
        assertThat(jdbc.queryForObject("SELECT idempotency_scope FROM reach_ci_checks WHERE check_id = ?", String.class,
                check.id())).isEqualTo("SYSTEM");
        assertThat(dispatcher.calls).containsExactly(new Call("service-backend", Map.of("check_id",
                Long.toString(check.id()), "target_type", "IMAGE", "commit", "", "path", "",
                "image_repository", "logssey/reused-api", "image_digest", "sha256:main", "rescan_of", Long.toString(done))));

        // 같은 날 다시 부르면 그 검사를 주고 띄우지 않는다. 다음 날은 새로
        dispatcher.calls.clear();
        assertThat(service.createRescan(done, day).orElseThrow().replayed()).isTrue();
        assertThat(dispatcher.calls).isEmpty();
        assertThat(service.createRescan(done, day.plusDays(1)).orElseThrow().replayed()).isFalse();
        assertThat(dispatcher.calls).hasSize(1);

        // 안 끝난 스캔은 재대조하지 않는다(422). 띄우는 설정이 없으면 만들지 않는다
        long running = scan(target, "RUNNING");
        assertError(() -> service.createRescan(running, day), ErrorCode.UNPROCESSABLE);
        dispatcher.enabled = false;
        long before = jdbc.queryForObject("SELECT count(*) FROM reach_ci_checks", Long.class);
        assertThat(service.createRescan(done, day.plusDays(2))).isEmpty();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM reach_ci_checks", Long.class)).isEqualTo(before);
    }

    @Test
    void rescanSbomIsTheStoredSbomOfTheOriginalScan() {
        long target = imageTarget();
        long done = scan(target, "SUCCEEDED");
        var plain = service.create("admin", "p", image("MANUAL", "logssey/reused-api", DIGEST)).check();
        var rescan = service.create("admin", "r", request("SCHEDULE", null, done, null)).check();

        // 원래 스캔에 보관한 SBOM이 없으면(보관 전 스캔) 404, 재대조가 아닌 검사도 404, 없는 검사도 404
        assertError(() -> service.sbom("admin", rescan.id()), ErrorCode.NOT_FOUND);
        assertError(() -> service.sbom("admin", plain.id()), ErrorCode.NOT_FOUND);
        assertError(() -> service.sbom("admin", 999), ErrorCode.NOT_FOUND);
        assertError(() -> service.sbom(null, rescan.id()), ErrorCode.UNAUTHENTICATED);

        byte[] gzip = {31, -117, 8, 0, 1, 2, 3};
        jdbc.update("INSERT INTO reach_sboms (scan_id, content_gzip, content_sha256, component_count) VALUES (?, ?, ?, 3)",
                done, gzip, "0".repeat(64));
        assertThat(service.sbom("admin", rescan.id())).isEqualTo(gzip);
    }

    private static long imageCheckScan(long checkId) {
        return jdbc.queryForObject("SELECT scan_id FROM reach_ci_checks WHERE check_id = ?", Long.class, checkId);
    }

    private record Call(String repository, Map<String, String> inputs) {}

    private static final class RecordingDispatcher implements ReachScanDispatcher {
        final List<Call> calls = new java.util.ArrayList<>();
        boolean enabled = true;

        @Override
        public boolean enabled() {
            return enabled;
        }

        @Override
        public void dispatch(String repository, Map<String, String> inputs) {
            calls.add(new Call(repository, Map.copyOf(inputs)));
        }
    }

    @Test
    void listShowsNewestChecksFirstWithFiltersAndCursor() {
        long a = service.create("admin", "a", pr("GATE")).check().id();
        long b = service.create("admin", "b", image("IMAGE_BUILD", "logssey/reused-api", DIGEST)).check().id();
        long c = service.create("admin", "c", new ReachCiCheckRequest("PR", "Logssey/service-frontend", COMMIT,
                new ReachCiCheckRequest.PullRequest(7, "main", "feature"), repoOf("service-frontend", null),
                null, null, null)).check().id();
        // b의 스캔만 끝난 것으로 둔다. 끝난 검사는 게이트를 함께 준다(새 Finding 없음 → PASS)
        jdbc.update("UPDATE reach_scans SET scan_status = 'SUCCEEDED', started_at = now(), finished_at = now() "
                + "WHERE scan_id = (SELECT scan_id FROM reach_ci_checks WHERE check_id = ?)", b);

        var all = service.checks("admin", filter(null, null, null), null, null, "total");
        assertThat(all.items()).extracting(ReachCiCheckResponse::id).containsExactly(c, b, a);
        assertThat(all.totalCount()).isEqualTo(3);
        assertThat(all.hasNext()).isFalse();
        assertThat(all.nextCursor()).isNull();
        var done = all.items().get(1);
        assertThat(done.gate().result()).isEqualTo("PASS");
        assertThat(done.createdAt()).isNotNull();
        assertThat(done.finishedAt()).isNotNull();
        assertThat(all.items().get(0).gate()).isNull();                    // 아직 안 끝났다
        assertThat(all.items().get(0).pullRequest().number()).isEqualTo(7);
        assertThat(service.checks("admin", filter(null, null, null), null, null, null).totalCount()).isNull();

        // 커서로 이어 받는다
        var first = service.checks("admin", filter(null, null, null), 2, null, null);
        assertThat(first.items()).extracting(ReachCiCheckResponse::id).containsExactly(c, b);
        assertThat(first.hasNext()).isTrue();
        var second = service.checks("admin", filter(null, null, null), 2, first.nextCursor(), null);
        assertThat(second.items()).extracting(ReachCiCheckResponse::id).containsExactly(a);
        assertThat(second.hasNext()).isFalse();

        // 필터: 실행 종류, 스캔 상태, 레포(대소문자·소유자 무시)
        assertThat(service.checks("admin", filter(null, List.of("IMAGE_BUILD"), null), null, null, null).items())
                .extracting(ReachCiCheckResponse::id).containsExactly(b);
        assertThat(service.checks("admin", filter(null, List.of("PR"), List.of("QUEUED")), null, null, null).items())
                .extracting(ReachCiCheckResponse::id).containsExactly(c, a);
        assertThat(service.checks("admin", filter(null, null, List.of("SUCCEEDED")), null, null, null).items())
                .extracting(ReachCiCheckResponse::id).containsExactly(b);
        assertThat(service.checks("admin", filter("Service-Backend", null, null), null, null, null).items())
                .extracting(ReachCiCheckResponse::id).containsExactly(b, a);
        assertThat(service.checks("admin", filter("logssey/service-frontend", null, null), null, null, null).items())
                .extracting(ReachCiCheckResponse::id).containsExactly(c);
        assertThat(service.checks("admin", filter("dashboard-backend", null, null), null, null, null).items()).isEmpty();

        // 400: 커서와 다른 필터, 크기 범위, include 값, 깨진 커서, 허용 밖 값
        assertError(() -> service.checks("admin", filter(null, List.of("PR"), null), 2, first.nextCursor(), null),
                ErrorCode.INVALID_INPUT);
        assertError(() -> service.checks("admin", filter(null, null, null), 0, null, null), ErrorCode.INVALID_INPUT);
        assertError(() -> service.checks("admin", filter(null, null, null), 101, null, null), ErrorCode.INVALID_INPUT);
        assertError(() -> service.checks("admin", filter(null, null, null), null, null, "all"), ErrorCode.INVALID_INPUT);
        assertError(() -> service.checks("admin", filter(null, null, null), null, "!!", null), ErrorCode.INVALID_INPUT);
        assertError(() -> filter(null, List.of("NIGHTLY"), null), ErrorCode.INVALID_INPUT);
        assertError(() -> filter(null, null, List.of("DONE")), ErrorCode.INVALID_INPUT);

        assertError(() -> service.checks(null, filter(null, null, null), null, null, null), ErrorCode.UNAUTHENTICATED);
        assertError(() -> service.checks("nobody", filter(null, null, null), null, null, null), ErrorCode.FORBIDDEN);
    }

    private static ReachCiCheckFilter filter(String repository, List<String> mode, List<String> scanStatus) {
        return new ReachCiCheckFilter(repository, mode, scanStatus);
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

    private static ReachTargetRequest repoOf(String name, String path) {
        return new ReachTargetRequest("REPO", null, new ReachTargetRequest.Repo(name, COMMIT, path), null);
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
