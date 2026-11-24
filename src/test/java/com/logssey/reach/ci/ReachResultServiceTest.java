package com.logssey.reach.ci;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.reach.l1.ReachL1Repository;
import com.logssey.reach.l1.ReachL1Service;
import com.logssey.reach.review.ReachReviewRepository;
import com.logssey.reach.review.ReachReviewRequest;
import com.logssey.reach.review.ReachReviewService;
import com.logssey.reach.ReachTestProperties;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ReachResultServiceTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final JsonMapper MAPPER = JsonMapper.builder().build();
    private static JdbcTemplate jdbc;
    private static DataSourceTransactionManager manager;
    private ReachResultService service;
    private ReachL1Service l1;
    private ReachCiCheckService checks;
    private ReachReviewService reviews;

    @BeforeAll
    static void startDatabase() {
        POSTGRES.start();
        var datasource = new DriverManagerDataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        Flyway.configure().dataSource(datasource).load().migrate();   // 버전 번호를 적지 않는다
        jdbc = new JdbcTemplate(datasource);
        manager = new DataSourceTransactionManager(datasource);      // 업로드는 트랜잭션 되돌리기까지 본다
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @BeforeEach
    void reset() {
        jdbc.execute("TRUNCATE reach_workloads, reach_workload_observations, reach_ci_checks, reach_review_history, "
                + "reach_reviews, reach_evidence, reach_verdicts, reach_findings, reach_scans, reach_targets, dashboard_users "
                + "RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO dashboard_users (login_id, password_hash, display_name, role) "
                + "VALUES ('admin', 'h', 'Admin', 'ADMIN')");
        var client = JdbcClient.create(jdbc);
        l1 = new ReachL1Service(new ReachL1Repository(client), ReachTestProperties.REUSED);
        service = new ReachResultService(new ReachResultRepository(client), l1, manager);
        checks = new ReachCiCheckService(new ReachCiCheckRepository(client), ReachTestProperties.REUSED);
        reviews = new ReachReviewService(new ReachReviewRepository(client));
    }

    @Test
    void requiresAdminGzipAndSizeLimits() {
        long check = check("a");
        byte[] body = gzip(bundle(List.of()));
        assertError(() -> service.upload(null, check, "gzip", body), ErrorCode.UNAUTHENTICATED);
        assertError(() -> service.upload("nobody", check, "gzip", body), ErrorCode.FORBIDDEN);
        assertError(() -> service.upload("admin", check, null, body), ErrorCode.INVALID_INPUT);
        assertError(() -> service.upload("admin", check, "gzip", "{}".getBytes()), ErrorCode.INVALID_INPUT);   // gzip 아님
        assertError(() -> service.upload("admin", check, "gzip", gzip("{not json")), ErrorCode.INVALID_INPUT);
        assertError(() -> service.upload("admin", check, "gzip", new byte[ReachResultService.COMPRESSED_MAX + 1]),
                ErrorCode.PAYLOAD_TOO_LARGE);
        // 0만 채운 큰 본문은 아주 작게 압축된다. 풀었을 때 한도를 넘으면 413
        assertError(() -> service.upload("admin", check, "gzip", gzip(new byte[ReachResultService.UNCOMPRESSED_MAX + 1])),
                ErrorCode.PAYLOAD_TOO_LARGE);
        assertError(() -> service.upload("admin", 999, "gzip", body), ErrorCode.NOT_FOUND);
        assertThat(scanStatus(check)).isEqualTo("QUEUED");
    }

    @Test
    @SuppressWarnings("unchecked")   // 테스트 묶음을 Map으로 만들어서 verdict를 꺼낼 때 형변환한다
    void storesFindingsVerdictsEvidenceAndFinishesTheScan() {
        long check = check("a");
        var unreachable = item("jackson-core", "CVE-2026-89407", "high", "unreachable", "rule", null,
                List.of(map("kind", "fact", "factId", "F-dto.floating.tokens", "value", false, "checkedCount", 97,
                                "summary", "tokens 97개에 실수형 필드 없음"),
                        map("kind", "rule", "ruleId", "RULE-CVE-2026-89407", "matchedCondition", "unreachable",
                                "summary", "도달 불가 조건")));
        var osPackage = item("zlib", "CVE-2026-85091", "medium", "not_analyzed", null, "os_package", List.of());
        osPackage.put("component", map("purl", "pkg:apk/alpine/zlib@1.3.2-r0", "name", "zlib", "version", "1.3.2-r0"));
        osPackage.put("proposal", map("status", "unreachable", "summary", "앱이 압축을 쓰지 않는다"));
        var reachable = item("tomcat-embed-core", "CVE-2026-65182", "critical", "reachable", "callgraph", null,
                List.of(map("kind", "path", "path", List.of("A.main", "B.run"), "pathTarget", "vuln_function",
                        "candidate", true, "summary", "후보 경로")));
        reachable.put("verdict", withCallgraph((Map<String, Object>) reachable.get("verdict")));

        var response = service.upload("admin", check, "gzip", gzip(bundle(List.of(unreachable, osPackage, reachable))));
        assertThat(response.scanStatus()).isEqualTo("SUCCEEDED");
        long scanId = response.scanId();
        assertThat(jdbc.queryForMap("SELECT scan_status, started_at IS NOT NULL AS started, finished_at IS NOT NULL AS finished, "
                + "tools->>'trivy' AS trivy, stages->0->>'name' AS stage FROM reach_scans WHERE scan_id = ?", scanId))
                .containsEntry("scan_status", "SUCCEEDED").containsEntry("started", true).containsEntry("finished", true)
                .containsEntry("trivy", "0.69.3").containsEntry("stage", "SBOM");

        // 소문자 열거값은 대문자로, ecosystem은 purl 타입으로 채운다
        assertThat(jdbc.queryForMap("SELECT severity, ecosystem, sources[1] AS source, fixed_versions[1] AS fixed, deployment "
                + "FROM reach_findings WHERE vulnerability_id = 'CVE-2026-85091'"))
                .containsEntry("severity", "MEDIUM").containsEntry("ecosystem", "apk").containsEntry("source", "TRIVY")
                .containsEntry("fixed", "1.0.1").containsEntry("deployment", "UNKNOWN");
        assertThat(jdbc.queryForList("SELECT v.status || ':' || COALESCE(v.method, v.not_analyzed_reason) FROM reach_verdicts v "
                + "WHERE v.is_current ORDER BY v.finding_id", String.class))
                .containsExactly("UNREACHABLE:RULE", "NOT_ANALYZED:OS_PACKAGE", "REACHABLE:CALLGRAPH");

        // 근거는 배열 순서로 order를 매기고, 칸이 아닌 필드는 detail에 API 이름 그대로 둔다
        var evidence = jdbc.queryForList("""
                SELECT e.ord, e.kind, e.fact_id, e.rule_id, e.detail::text AS detail
                FROM reach_evidence e JOIN reach_verdicts v ON v.verdict_id = e.verdict_id
                JOIN reach_findings f ON f.finding_id = v.finding_id
                WHERE f.vulnerability_id = 'CVE-2026-89407' ORDER BY e.ord
                """);
        assertThat(evidence).hasSize(2);
        assertThat(evidence.get(0)).containsEntry("kind", "FACT").containsEntry("fact_id", "F-dto.floating.tokens");
        assertThat((String) evidence.get(0).get("detail")).contains("\"checkedCount\": 97").doesNotContain("summary");
        assertThat((String) evidence.get(1).get("detail")).contains("\"matchedCondition\": \"UNREACHABLE\"");
        assertThat(jdbc.queryForObject("SELECT callgraph->>'entryStage' FROM reach_verdicts v JOIN reach_findings f "
                + "ON f.finding_id = v.finding_id WHERE f.vulnerability_id = 'CVE-2026-65182'", String.class)).isEqualTo("1");

        // 새 Finding은 검토 전 version 1, 처음 행이라 이력이 없다. 제안은 검토 전 행에 둔다
        assertThat(jdbc.queryForList("SELECT review_state || ':' || version FROM reach_reviews", String.class))
                .containsOnly("UNREVIEWED:1");
        assertThat(jdbc.queryForObject("SELECT proposal->>'status' FROM reach_reviews r JOIN reach_findings f "
                + "ON f.finding_id = r.finding_id WHERE f.vulnerability_id = 'CVE-2026-85091'", String.class))
                .isEqualTo("UNREACHABLE");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM reach_review_history", Long.class)).isZero();

        // SBOM은 재대조 입력으로 스캔마다 gzip으로 보관한다 (V53). 해시는 푼 JSON의 것, 구성요소 수는 components 개수
        var sbom = jdbc.queryForMap("SELECT content_gzip, content_sha256, component_count FROM reach_sboms WHERE scan_id = ?", scanId);
        String json;
        try (var in = new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream((byte[]) sbom.get("content_gzip")))) {
            json = new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        } catch (java.io.IOException e) {
            throw new AssertionError(e);
        }
        assertThat(json).contains("\"bomFormat\":\"CycloneDX\"").contains("\"name\":\"jackson-core\"");
        assertThat(sbom).containsEntry("component_count", 2);
        assertThat((String) sbom.get("content_sha256")).isEqualTo(ReachCiCheckService.sha256(json));

        // 같은 검사에 다시 올리면 409
        assertError(() -> service.upload("admin", check, "gzip", gzip(bundle(List.of()))), ErrorCode.CONFLICT);
    }

    @Test
    void rejectsBundlesThatBreakTheRulesWithoutSavingAnything() {
        long check = check("a");
        var noEvidence = item("a", "CVE-2026-1", "HIGH", "UNREACHABLE", "RULE", null, List.of());
        var notAnalyzedWithMethod = item("a", "CVE-2026-1", "HIGH", "NOT_ANALYZED", "RULE", "OS_PACKAGE", List.of());
        var manual = item("a", "CVE-2026-1", "HIGH", "REACHABLE", "MANUAL", null, List.of());
        var badSeverity = item("a", "CVE-2026-1", "SEVERE", "REACHABLE", "CALLGRAPH", null, List.of());
        var factWithoutId = item("a", "CVE-2026-1", "HIGH", "UNREACHABLE", "RULE", null,
                List.of(map("kind", "FACT", "summary", "x")));
        var ok = item("a", "CVE-2026-1", "HIGH", "REACHABLE", "CALLGRAPH", null, List.of());
        // 배열 칸의 null·빈 값은 저장하면 배열 안의 NULL이 되어 목록·상세가 깨진다
        var nullFixedVersion = item("a", "CVE-2026-1", "HIGH", "REACHABLE", "CALLGRAPH", null, List.of());
        nullFixedVersion.put("vulnerability", map("id", "CVE-2026-1", "severity", "HIGH", "fixedVersions", Arrays.asList("1.0.1", null)));
        var blankCwe = item("a", "CVE-2026-1", "HIGH", "REACHABLE", "CALLGRAPH", null, List.of());
        blankCwe.put("vulnerability", map("id", "CVE-2026-1", "severity", "HIGH", "cwe", List.of(" ")));
        var nullVulnFunction = item("a", "CVE-2026-1", "HIGH", "REACHABLE", "CALLGRAPH", null, List.of());
        nullVulnFunction.put("verdict", map("status", "REACHABLE", "method", "CALLGRAPH", "summary", "test",
                "vulnFunctionIds", Arrays.asList(1, null), "engine", map("reach", "v0")));

        for (var items : List.of(List.of(noEvidence), List.of(notAnalyzedWithMethod), List.of(manual),
                List.of(badSeverity), List.of(factWithoutId), List.of(nullFixedVersion), List.of(blankCwe),
                List.of(nullVulnFunction), List.of(ok, ok))) {   // 마지막은 같은 purl × CVE 두 번
            assertError(() -> service.upload("admin", check, "gzip", gzip(bundle(items))), ErrorCode.INVALID_INPUT);
        }
        var noSbom = bundle(List.of(ok));
        noSbom.remove("sbom");
        assertError(() -> service.upload("admin", check, "gzip", gzip(noSbom)), ErrorCode.INVALID_INPUT);

        assertThat(scanStatus(check)).isEqualTo("QUEUED");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM reach_findings", Long.class)).isZero();
    }

    @Test
    void failureBundleEndsTheScanAsFailed() {
        long check = check("a");
        var failed = map("tools", map("cdxgen", "11.0.0"),
                "stages", List.of(map("name", "sbom", "status", "failed", "durationSeconds", 12)),
                "failure", map("code", "BUILD_FAILED", "stage", "sbom", "message", "Gradle build failed"));
        var response = service.upload("admin", check, "gzip", gzip(failed));
        assertThat(response.scanStatus()).isEqualTo("FAILED");
        assertThat(jdbc.queryForMap("SELECT scan_status, failure_code, failure_stage, finished_at IS NOT NULL AS finished "
                + "FROM reach_scans WHERE scan_id = ?", response.scanId()))
                .containsEntry("scan_status", "FAILED").containsEntry("failure_code", "BUILD_FAILED")
                .containsEntry("failure_stage", "SBOM").containsEntry("finished", true);
        assertError(() -> service.upload("admin", check, "gzip", gzip(failed)), ErrorCode.CONFLICT);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM reach_sboms", Long.class)).isZero();   // 실패 묶음은 SBOM이 없다
    }

    @Test
    void anUploadWaitsForAReviewBeingSavedAndThenJudgesIt() throws Exception {
        var evidence = List.of(map("kind", "NOTE", "summary", "no path"));
        upload(check("a"), item("a", "CVE-2026-1", "HIGH", "UNREACHABLE", "CALLGRAPH", null, evidence));
        long a = finding("a");
        long base = jdbc.queryForObject("SELECT verdict_id FROM reach_verdicts WHERE finding_id = ? AND is_current", Long.class, a);

        // a person is saving UNREACHABLE (API-06 holds the review row in its transaction, not committed yet)
        try (var person = jdbc.getDataSource().getConnection()) {
            person.setAutoCommit(false);
            try (var lock = person.prepareStatement("SELECT 1 FROM reach_reviews WHERE finding_id = ? FOR UPDATE")) {
                lock.setLong(1, a);
                lock.executeQuery().close();
            }
            try (var save = person.prepareStatement("""
                    UPDATE reach_reviews SET review_state = 'CONFIRMED', status = 'UNREACHABLE', note = 'checked',
                           reviewer_user_id = 1, reviewed_at = now(), version = version + 1, base_verdict_id = ?
                    WHERE finding_id = ?""")) {
                save.setLong(1, base);
                save.setLong(2, a);
                save.executeUpdate();
            }

            // meanwhile the next scan says REACHABLE: it must wait for that save, not read the old UNREVIEWED row
            var next = new java.util.concurrent.CompletableFuture<Long>();
            long nextCheck = check("a");
            var uploader = new Thread(() -> {
                try {
                    next.complete(upload(nextCheck, item("a", "CVE-2026-1", "HIGH", "REACHABLE", "CALLGRAPH", null, evidence)));
                } catch (Throwable e) {
                    next.completeExceptionally(e);
                }
            });
            uploader.start();
            Thread.sleep(1500);
            assertThat(next).isNotDone();
            person.commit();
            next.get(30, java.util.concurrent.TimeUnit.SECONDS);
        }
        // it saw the person's UNREACHABLE and reset it against the new REACHABLE
        assertThat(review(a)).isEqualTo("UNREVIEWED:3:VERDICT_CHANGED");
    }

    @Test
    void nextScanOfTheSameTargetKeepsAnUnchangedReviewAndResetsAChangedOne() {
        var evidence = List.of(map("kind", "NOTE", "summary", "no path"));
        upload(check("a"), item("a", "CVE-2026-1", "HIGH", "UNREACHABLE", "CALLGRAPH", null, evidence),
                item("b", "CVE-2026-2", "HIGH", "UNREACHABLE", "CALLGRAPH", null, evidence));
        long a = finding("a");
        long b = finding("b");
        var firstSeen = jdbc.queryForObject("SELECT first_seen_at FROM reach_findings WHERE finding_id = ?", Object.class, a);
        confirm(a, "UNREACHABLE", 1);
        confirm(b, "UNREACHABLE", 1);

        // 같은 이미지를 다시 스캔: a는 판정·근거가 같고, b는 근거만 바뀌었다
        long second = upload(check("a"), item("a", "CVE-2026-1", "HIGH", "UNREACHABLE", "CALLGRAPH", null, evidence),
                item("b", "CVE-2026-2", "HIGH", "UNREACHABLE", "CALLGRAPH", null,
                        List.of(map("kind", "NOTE", "summary", "another path checked"))));
        assertThat(finding("a")).isEqualTo(a);   // 같은 Finding을 갱신한다
        assertThat(jdbc.queryForMap("SELECT last_scan_id, first_seen_at FROM reach_findings WHERE finding_id = ?", a))
                .containsEntry("last_scan_id", second).containsEntry("first_seen_at", firstSeen);
        assertThat(review(a)).isEqualTo("CONFIRMED:2:null");
        assertThat(review(b)).isEqualTo("UNREVIEWED:3:EVIDENCE_CHANGED");
        assertThat(jdbc.queryForObject("SELECT scan_id FROM reach_verdicts WHERE finding_id = ? AND is_current", Long.class, a))
                .isEqualTo(second);

        // 판정 상태가 바뀌면 VERDICT_CHANGED. 사람 판정은 이력의 앞 version에 남는다
        upload(check("a"), item("a", "CVE-2026-1", "HIGH", "REACHABLE", "CALLGRAPH", null, evidence));
        assertThat(review(a)).isEqualTo("UNREVIEWED:3:VERDICT_CHANGED");
        assertThat(history(a)).containsExactly("2:HUMAN:CONFIRMED", "3:RESET:UNREVIEWED");
    }

    @Test
    void anUploadThatStartedEarlierThanTheOneAlreadyStoredDoesNotMoveLastSeenBack() {
        var evidence = List.of(map("kind", "NOTE", "summary", "no path"));
        upload(check("a"), item("a", "CVE-2026-1", "HIGH", "UNREACHABLE", "CALLGRAPH", null, evidence));
        long a = finding("a");
        // 겹친 두 업로드 가운데 나중에 시작한 쪽이 먼저 반영된 상태: 저장된 시각이 다음 업로드의 now()보다 늦다
        jdbc.update("UPDATE reach_findings SET first_seen_at = now() + interval '1 hour', "
                + "last_seen_at = now() + interval '1 hour' WHERE finding_id = ?", a);
        var seen = jdbc.queryForMap("SELECT first_seen_at, last_seen_at FROM reach_findings WHERE finding_id = ?", a);

        long second = upload(check("a"), item("a", "CVE-2026-1", "HIGH", "UNREACHABLE", "CALLGRAPH", null, evidence));

        assertThat(jdbc.queryForMap("SELECT last_scan_id, first_seen_at, last_seen_at FROM reach_findings WHERE finding_id = ?", a))
                .containsEntry("last_scan_id", second)
                .containsEntry("first_seen_at", seen.get("first_seen_at"))
                .containsEntry("last_seen_at", seen.get("last_seen_at"));
    }

    @Test
    void newImageOfTheSameAppCarriesTheReviewAndResetsItWhenTheVerdictChanged() {
        var evidence = List.of(map("kind", "NOTE", "summary", "no path"));
        upload(check("a"), item("a", "CVE-2026-1", "HIGH", "UNREACHABLE", "CALLGRAPH", null, evidence),
                item("b", "CVE-2026-2", "HIGH", "UNREACHABLE", "CALLGRAPH", null, evidence));
        long oldA = finding("a");
        long oldB = finding("b");
        long oldScan = jdbc.queryForObject("SELECT last_scan_id FROM reach_findings WHERE finding_id = ?", Long.class, oldA);
        confirm(oldA, "UNREACHABLE", 1);
        confirm(oldB, "UNREACHABLE", 1);

        // 새 digest라 대상이 다르다. a는 같은 판정이라 이어받고, b는 판정이 바뀌어 이어받은 뒤 되돌린다
        upload(check("b"), item("a", "CVE-2026-1", "HIGH", "UNREACHABLE", "CALLGRAPH", null, evidence),
                item("b", "CVE-2026-2", "HIGH", "REACHABLE", "CALLGRAPH", null, evidence));
        long newA = jdbc.queryForObject("SELECT max(finding_id) FROM reach_findings WHERE component_name = 'a'", Long.class);
        long newB = jdbc.queryForObject("SELECT max(finding_id) FROM reach_findings WHERE component_name = 'b'", Long.class);
        assertThat(newA).isNotEqualTo(oldA);
        assertThat(jdbc.queryForMap("SELECT review_state, status, note, reviewer_user_id, carried_from_finding_id, "
                + "carried_from_scan_id, reviewed_at = (SELECT reviewed_at FROM reach_reviews WHERE finding_id = ?) AS same_time "
                + "FROM reach_reviews WHERE finding_id = ?", oldA, newA))
                .containsEntry("review_state", "CONFIRMED").containsEntry("status", "UNREACHABLE")
                .containsEntry("note", "checked").containsEntry("reviewer_user_id", 1L)
                .containsEntry("carried_from_finding_id", oldA).containsEntry("carried_from_scan_id", oldScan)
                .containsEntry("same_time", true);
        assertThat(history(newA)).containsExactly("1:CARRIED:CONFIRMED");
        assertThat(review(newB)).isEqualTo("UNREVIEWED:2:VERDICT_CHANGED");
        assertThat(history(newB)).containsExactly("1:CARRIED:CONFIRMED", "2:RESET:UNREVIEWED");
    }

    @Test
    void prResultsNeitherCarryNorBecomeTheSource() {
        var evidence = List.of(map("kind", "NOTE", "summary", "no path"));
        var a = item("a", "CVE-2026-1", "HIGH", "UNREACHABLE", "CALLGRAPH", null, evidence);
        upload(check("a"), a);
        long image = finding("a");
        long imageScan = jdbc.queryForObject("SELECT last_scan_id FROM reach_findings WHERE finding_id = ?", Long.class, image);
        confirm(image, "UNREACHABLE", 1);

        // PR 검사는 같은 서비스(API)여도 이어받지 않는다 (ARD SR-09)
        upload(prCheck("c"), a);
        long pr = jdbc.queryForObject("SELECT max(finding_id) FROM reach_findings WHERE component_name = 'a'", Long.class);
        assertThat(pr).isNotEqualTo(image);
        assertThat(review(pr)).isEqualTo("UNREVIEWED:1:null");
        assertThat(history(pr)).isEmpty();

        // PR Finding을 확정해 가장 최근 검토가 되어도, 다음 이미지는 PR이 아닌 Finding에서 이어받는다
        confirm(pr, "UNREACHABLE", 1);
        upload(check("b"), a);
        long next = jdbc.queryForObject("SELECT max(finding_id) FROM reach_findings WHERE component_name = 'a'", Long.class);
        assertThat(jdbc.queryForMap("SELECT carried_from_finding_id, carried_from_scan_id FROM reach_reviews WHERE finding_id = ?", next))
                .containsEntry("carried_from_finding_id", image).containsEntry("carried_from_scan_id", imageScan);
    }

    @Test
    void prRescanOfAnAlreadyScannedCommitLeavesTheBaselineFindingAlone() {
        var evidence = List.of(map("kind", "NOTE", "summary", "no path"));
        long schedule = upload(repoCheck("SCHEDULE", "d"), item("a", "CVE-2026-1", "HIGH", "UNREACHABLE", "CALLGRAPH", null, evidence));
        long a = finding("a");
        long baseline = currentVerdict(a);
        confirm(a, "UNREACHABLE", 1);

        // develop → main PR처럼 이미 스캔한 커밋을 PR로 다시 스캔하면 같은 대상이라 같은 Finding을 만난다.
        // PR 결과는 그 스캔의 판정으로만 남고 기준 Finding의 칸·현재 판정·사람 검토는 그대로다 (ARD SR-09)
        long pr = upload(repoCheck("PR", "d"), item("a", "CVE-2026-1", "CRITICAL", "REACHABLE", "CALLGRAPH", null, evidence));
        assertThat(finding("a")).isEqualTo(a);
        assertThat(currentVerdict(a)).isEqualTo(baseline);
        assertThat(review(a)).isEqualTo("CONFIRMED:2:null");
        assertThat(history(a)).containsExactly("2:HUMAN:CONFIRMED");
        assertThat(jdbc.queryForMap("SELECT last_scan_id, severity FROM reach_findings WHERE finding_id = ?", a))
                .containsEntry("last_scan_id", schedule).containsEntry("severity", "HIGH");
        assertThat(jdbc.queryForObject("SELECT status FROM reach_verdicts WHERE finding_id = ? AND scan_id = ? AND NOT is_current",
                String.class, a, pr)).isEqualTo("REACHABLE");
    }

    @Test
    void humanVerdictOnANotAnalyzedFindingStaysCurrentAndIsCarried() {
        var notAnalyzed = item("a", "CVE-2026-1", "HIGH", "NOT_ANALYZED", null, "UNANALYZED_COPY", List.of());
        upload(check("a"), notAnalyzed);
        long a = finding("a");
        confirm(a, "UNREACHABLE", 1);   // API-06 예외: MANUAL 판정이 현재 판정이 된다
        long manual = currentVerdict(a);

        upload(check("a"), notAnalyzed);   // 다시 NOT_ANALYZED → MANUAL 그대로
        assertThat(currentVerdict(a)).isEqualTo(manual);
        assertThat(review(a)).isEqualTo("CONFIRMED:2:null");

        upload(check("b"), notAnalyzed);   // 새 이미지로 이어받으면 그 Finding에도 MANUAL 판정을 만든다
        long newA = jdbc.queryForObject("SELECT max(finding_id) FROM reach_findings", Long.class);
        assertThat(jdbc.queryForMap("SELECT status, method, created_by_user_id, summary FROM reach_verdicts "
                + "WHERE finding_id = ? AND is_current", newA))
                .containsEntry("status", "UNREACHABLE").containsEntry("method", "MANUAL")
                .containsEntry("created_by_user_id", 1L).containsEntry("summary", "checked");
    }

    @Test
    void imageFindingsTakeDeploymentFromL1AndKeepItOnReupload() {
        observe("a");   // 클러스터에서 digest a가 돌고 있다
        var item = item("a", "CVE-2026-1", "HIGH", "REACHABLE", "CALLGRAPH", null, List.of());

        upload(check("a"), item);   // 묶음에는 deployment가 없다(UNKNOWN)
        long a = finding("a");
        assertThat(deployment(a)).isEqualTo("RUNNING");   // 새 Finding도 업로드 끝에서 바로 계산된다

        item.put("deployment", "not_running");
        upload(check("a"), item);   // 같은 대상을 다시 스캔해도 묶음 값으로 덮지 않는다
        assertThat(deployment(a)).isEqualTo("RUNNING");

        long b = upload(check("b"), item("b", "CVE-2026-2", "HIGH", "REACHABLE", "CALLGRAPH", null, List.of()));
        observe("a");   // 대상 b가 생긴 뒤의 조회에도 b는 없다
        l1.recompute(null);
        assertThat(jdbc.queryForObject("SELECT deployment FROM reach_findings WHERE last_scan_id = ?", String.class, b))
                .isEqualTo("NOT_RUNNING");
    }

    @Test
    void repoFindingsKeepTheBundleDeploymentFromTheFirstUpload() {
        observe("d");
        var item = item("a", "CVE-2026-1", "HIGH", "REACHABLE", "CALLGRAPH", null, List.of());
        item.put("deployment", "running");
        upload(repoCheck("SCHEDULE", "d"), item);   // L1 재계산은 이미지 대상만 본다
        long a = finding("a");
        assertThat(deployment(a)).isEqualTo("RUNNING");

        item.put("deployment", "unknown");
        upload(repoCheck("SCHEDULE", "d"), item);
        assertThat(deployment(a)).isEqualTo("RUNNING");
    }

    @Test
    void l3IsStoredAndRaisesTheVerdictOnlyWhenItSawTheVulnerableCodeRun() {
        var evidence = List.of(map("kind", "NOTE", "summary", "no path"));
        long scan = uploadWithL3(check("a"),
                l3(l3Cve("CVE-2026-1", "a", "region", true, false), l3Cve("CVE-2026-2", "b", "FUNCTION", true, false),
                        l3Cve("CVE-2026-4", "d", "FUNCTION", false, false), l3Cve("CVE-2026-5", "e", "REGION", true, true),
                        l3Cve("CVE-2026-6", "g", "NONE", true, false),
                        l3Cve("CVE-2026-9", "not-in-this-scan", "NONE", true, false)),
                item("a", "CVE-2026-1", "HIGH", "UNREACHABLE", "CALLGRAPH", null, evidence),
                item("b", "CVE-2026-2", "HIGH", "UNREACHABLE", "CALLGRAPH", null, evidence),
                item("c", "CVE-2026-3", "HIGH", "NOT_ANALYZED", null, "NO_VULN_FUNCTION_DATA", List.of()),
                item("d", "CVE-2026-4", "HIGH", "UNREACHABLE", "CALLGRAPH", null, evidence),
                item("e", "CVE-2026-5", "HIGH", "UNKNOWN", "RULE", null, evidence),
                item("g", "CVE-2026-6", "HIGH", "UNREACHABLE", "CALLGRAPH", null, evidence));

        assertThat(jdbc.queryForMap("SELECT run_status, scenario, observation_method, error, counts->>'REGION' AS regions, "
                + "detail->'build'->>'imageDigest' AS digest, detail->'configKeys'->0->>'name' AS key, "
                + "jsonb_array_length(detail->'invocations') AS invocations, jsonb_exists(detail, 'secretValue') AS extra "
                + "FROM reach_l3_runs WHERE scan_id = ?", scan))
                .containsEntry("run_status", "SUCCEEDED").containsEntry("scenario", "2026-11-18.1")
                .containsEntry("observation_method", "COVERAGE").containsEntry("error", null)
                .containsEntry("regions", "1").containsEntry("digest", "sha256:abc").containsEntry("key", "KAKAO_STUB")
                .containsEntry("invocations", 2).containsEntry("extra", false);   // 모르는 칸은 담지 않는다
        // 취약 구간이 실행됐으면 도달 가능(L2가 도달 불가든 확인 못 함이든, 앱이 뜨는 동안만이어도).
        // 함수까지 실행됐는데 구간을 확인 못 했으면 도달 불가 → 확인 못 함. 구간을 봤고 실행 안 됨·실행 없음은 L2 그대로
        assertThat(jdbc.queryForList("SELECT f.component_name || ':' || v.status || ':' || v.method || ':' || x.reached "
                + "FROM reach_l3_results x JOIN reach_findings f ON f.finding_id = x.finding_id "
                + "JOIN reach_verdicts v ON v.finding_id = f.finding_id AND v.is_current ORDER BY 1", String.class))
                .containsExactly("a:REACHABLE:CALLGRAPH:REGION", "b:UNREACHABLE:CALLGRAPH:FUNCTION",
                        "d:UNKNOWN:CALLGRAPH:FUNCTION", "e:REACHABLE:RULE:REGION", "g:UNREACHABLE:CALLGRAPH:NONE");
        // 올린 판정은 L2 근거 뒤에 RUNTIME 한 줄. 스캔 번호·관측 시각은 넣지 않는다(근거 해시가 재대조마다 같게)
        assertThat(jdbc.queryForList("SELECT f.component_name || ':' || e.ord || ':' || (e.detail->>'l2Status') || ':' "
                + "|| (e.detail->>'executed') || ':' || (e.detail->>'startupOnly') || ':' || jsonb_exists(e.detail, 'scanId') "
                + "FROM reach_evidence e JOIN reach_verdicts v ON v.verdict_id = e.verdict_id "
                + "JOIN reach_findings f ON f.finding_id = v.finding_id WHERE e.kind = 'RUNTIME' ORDER BY 1", String.class))
                .containsExactly("a:2:UNREACHABLE:true:false:false", "d:2:UNREACHABLE:false:false:false",
                        "e:2:UNKNOWN:true:true:false");
        assertThat(jdbc.queryForObject("SELECT summary FROM reach_verdicts WHERE finding_id = ? AND is_current",
                String.class, finding("a"))).startsWith("L3: ").endsWith("L2 판정은 도달 불가였다: test");
        // 근거 해시도 L2 근거만의 해시와 다르다
        assertThat(jdbc.queryForObject("SELECT count(DISTINCT evidence_hash) FROM reach_verdicts v "
                + "JOIN reach_findings f ON f.finding_id = v.finding_id WHERE f.component_name IN ('a', 'b')", Long.class))
                .isEqualTo(2);
        assertThat(jdbc.queryForMap("SELECT detail->'during'->>0 AS during, detail->'regions'->0->'executedLines'->>0 AS line, "
                + "jsonb_exists(detail, 'reached') AS dup FROM reach_l3_results WHERE finding_id = ?", finding("a")))
                .containsEntry("during", "002").containsEntry("line", "626").containsEntry("dup", false);
    }

    @Test
    void anotherJarOfTheSameGroupTakesTheL3ResultOnlyWhenTheBundleGaveItTheVerdict() {
        // bundle.py가 판정 데이터 좌표(test:ws)의 판정을 준 같은 그룹의 다른 jar(test:core)는 그 L3 결과로 올라간다.
        // 판정하지 않은 사본(같은 그룹이어도 bundle.py가 NOT_ANALYZED로 둔 것: 버전이 다름 등)에는 붙이지 않는다
        var evidence = List.of(map("kind", "NOTE", "summary", "no path"));
        uploadWithL3(check("a"), l3(l3Cve("CVE-2026-1", "ws", "REGION", true, false)),
                item("core", "CVE-2026-1", "HIGH", "UNREACHABLE", "RULE", null, evidence),
                item("el", "CVE-2026-1", "HIGH", "NOT_ANALYZED", null, "UNANALYZED_COPY", List.of()));
        assertThat(l3Results()).hasSize(1).allMatch(r -> r.startsWith("core:REGION:"));
        assertThat(jdbc.queryForObject("SELECT status FROM reach_verdicts WHERE finding_id = ? AND is_current",
                String.class, finding("core"))).isEqualTo("REACHABLE");
    }

    @Test
    void anL3RaiseResetsAReviewOnceAndARescanWithoutTheAppKeepsIt() {
        var evidence = List.of(map("kind", "NOTE", "summary", "no path"));
        var a = item("a", "CVE-2026-1", "HIGH", "UNREACHABLE", "CALLGRAPH", null, evidence);
        var b = item("b", "CVE-2026-2", "HIGH", "UNREACHABLE", "CALLGRAPH", null, evidence);
        upload(check("a"), a, b);
        confirm(finding("a"), "UNREACHABLE", 1);
        confirm(finding("b"), "UNREACHABLE", 1);

        // 사람이 도달 불가로 확정했어도 L3가 취약 구간 실행을 봤으면 판정이 바뀌어 검토가 되돌아간다.
        // 구간을 확인 못 한 함수 실행(b)은 도달 불가 → 확인 못 함이라 역시 되돌아간다
        long observed = uploadWithL3(check("a"), l3(l3Cve("CVE-2026-1", "a", "REGION", true, false),
                l3Cve("CVE-2026-2", "b", "FUNCTION", false, true)), a, b);
        assertThat(review(finding("a"))).isEqualTo("UNREVIEWED:3:VERDICT_CHANGED");
        assertThat(review(finding("b"))).isEqualTo("UNREVIEWED:3:VERDICT_CHANGED");
        assertThat(currentStatus(finding("a"))).isEqualTo("REACHABLE");
        assertThat(currentStatus(finding("b"))).isEqualTo("UNKNOWN");
        confirm(finding("a"), "REACHABLE", 3);

        // 재대조는 앱을 띄우지 않는다(l3 없음): 남아 있는 L3 결과로 같은 판정·같은 근거 해시가 되어 검토가 남는다
        long rescan = upload(check("a"), a, b);
        assertThat(review(finding("a"))).isEqualTo("CONFIRMED:4:null");
        assertThat(currentStatus(finding("b"))).isEqualTo("UNKNOWN");
        assertThat(l3Results()).containsExactly("a:REGION:" + observed, "b:FUNCTION:" + observed);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM reach_l3_runs WHERE scan_id = ?", Long.class, rescan)).isZero();
        // 보관한 기록을 다시 대조해 같은 결과가 나와도(스캔 번호만 다름) 그대로다
        uploadWithL3(check("a"), l3(l3Cve("CVE-2026-1", "a", "REGION", true, false),
                l3Cve("CVE-2026-2", "b", "FUNCTION", false, true)), a, b);
        assertThat(review(finding("a"))).isEqualTo("CONFIRMED:4:null");

        // 같은 이미지를 다시 띄워 실행되지 않았으면 L2 판정으로 돌아가고(판정이 바뀌어 검토도 되돌아간다), 이번에 없는 결과는 지운다
        long again = uploadWithL3(check("a"), l3(l3Cve("CVE-2026-1", "a", "NONE", true, false)), a, b);
        assertThat(l3Results()).containsExactly("a:NONE:" + again);
        assertThat(currentStatus(finding("a"))).isEqualTo("UNREACHABLE");
        assertThat(review(finding("a"))).isEqualTo("UNREVIEWED:5:VERDICT_CHANGED");
        assertThat(currentStatus(finding("b"))).isEqualTo("UNREACHABLE");
    }

    @Test
    void aPrCheckIsNeverRaisedByL3() {
        var a = item("a", "CVE-2026-1", "HIGH", "UNREACHABLE", "CALLGRAPH", null, List.of(map("kind", "NOTE", "summary", "x")));
        uploadWithL3(check("a"), l3(l3Cve("CVE-2026-1", "a", "REGION", true, false)), a);
        assertThat(currentStatus(finding("a"))).isEqualTo("REACHABLE");

        // PR 검사는 앱을 띄우지 않는다. 그 스캔의 판정은 L2 그대로다(게이트는 이 값과 기준 스캔을 비교한다)
        long pr = uploadWithL3(prCheck("a"), l3(l3Cve("CVE-2026-1", "a", "REGION", true, false)), a);
        assertThat(jdbc.queryForList("SELECT v.status FROM reach_verdicts v WHERE v.scan_id = ?", String.class, pr))
                .containsExactly("UNREACHABLE");
        assertThat(currentStatus(finding("a"))).isEqualTo("REACHABLE");
    }

    private static String currentStatus(long findingId) {
        return jdbc.queryForObject("SELECT status FROM reach_verdicts WHERE finding_id = ? AND is_current", String.class, findingId);
    }

    @Test
    void aFailedOrBrokenL3StillFinishesTheScan() {
        var a = item("a", "CVE-2026-1", "HIGH", "UNREACHABLE", "CALLGRAPH", null, List.of(map("kind", "NOTE", "summary", "x")));
        long first = uploadWithL3(check("a"), l3(l3Cve("CVE-2026-1", "a", "REGION", true, false)), a);

        // 러너에서 L3가 실패했다: 스캔은 성공, 실행만 FAILED, 그 이미지의 예전 결과는 그대로
        long failed = uploadWithL3(check("a"), map("error", "L3 run failed on the runner, see the workflow log"), a);
        assertThat(jdbc.queryForMap("SELECT s.scan_status, r.run_status, r.error FROM reach_scans s "
                + "JOIN reach_l3_runs r ON r.scan_id = s.scan_id WHERE s.scan_id = ?", failed))
                .containsEntry("scan_status", "SUCCEEDED").containsEntry("run_status", "FAILED")
                .containsEntry("error", "L3 run failed on the runner, see the workflow log");
        assertThat(l3Results()).containsExactly("a:REGION:" + first);

        // 모양이 틀린 l3도 400이 아니다 (L3는 스캔을 실패시키지 않는다)
        var badLevel = l3(l3Cve("CVE-2026-1", "a", "MAYBE", true, false));
        var noRun = l3(l3Cve("CVE-2026-1", "a", "REGION", true, false));
        noRun.remove("run");
        var twice = l3(l3Cve("CVE-2026-1", "a", "REGION", true, false), l3Cve("CVE-2026-1", "a", "NONE", true, false));
        for (Object broken : Arrays.asList("not an object", badLevel, noRun, twice, map("cves", List.of()))) {
            long scan = uploadWithL3(check("a"), broken, a);
            assertThat(jdbc.queryForMap("SELECT s.scan_status, r.run_status, r.error FROM reach_scans s "
                    + "JOIN reach_l3_runs r ON r.scan_id = s.scan_id WHERE s.scan_id = ?", scan))
                    .containsEntry("scan_status", "SUCCEEDED").containsEntry("run_status", "FAILED")
                    .containsEntry("error", ReachL3Input.INVALID);
        }
        assertThat(l3Results()).containsExactly("a:REGION:" + first);
    }

    @Test
    void theExecutionRecordOfAFreshRunIsKeptForRescans() {
        var a = item("a", "CVE-2026-1", "HIGH", "UNREACHABLE", "CALLGRAPH", null, List.of(map("kind", "NOTE", "summary", "x")));
        byte[] record = xz("segments");
        long scan = uploadWithRecord(check("a"), l3(l3Cve("CVE-2026-1", "a", "REGION", true, false)), recordOf(record), a);
        assertThat(jdbc.queryForMap("SELECT format, byte_size, content_sha256, content FROM reach_l3_records WHERE scan_id = ?", scan))
                .containsEntry("format", "TAR_XZ").containsEntry("byte_size", record.length)
                .containsEntry("content", record)
                .containsEntry("content_sha256", java.util.HexFormat.of().formatHex(sha256(record)));

        // 보관한 기록으로 다시 대조한 결과(run.rematch)는 결과만 바꾸고 기록은 다시 받지 않는다
        var rematch = l3(l3Cve("CVE-2026-1", "a", "FUNCTION", true, false));
        ((Map<String, Object>) rematch.get("run")).put("rematch", true);
        long rescan = uploadWithRecord(check("a"), rematch, recordOf(xz("other")), a);
        assertThat(l3Results()).containsExactly("a:FUNCTION:" + rescan);
        assertThat(jdbc.queryForObject("SELECT (detail->>'rematch')::boolean FROM reach_l3_runs WHERE scan_id = ?", Boolean.class, rescan)).isTrue();
        assertThat(recordScans()).containsExactly(scan);

        // 틀린 기록은 버리고 결과는 그대로 저장한다. 실패한 L3·PR 검사에는 기록이 없다
        var plain = l3(l3Cve("CVE-2026-1", "a", "REGION", true, false));
        for (Object broken : Arrays.asList(map("format", "ZIP", "content", java.util.Base64.getEncoder().encodeToString(record)),
                map("format", "TAR_XZ", "content", "not base64 !!"),
                map("format", "TAR_XZ", "content", java.util.Base64.getEncoder().encodeToString("plain text".getBytes())), "text")) {
            long bad = uploadWithRecord(check("b"), plain, broken, a);
            assertThat(jdbc.queryForObject("SELECT run_status FROM reach_l3_runs WHERE scan_id = ?", String.class, bad)).isEqualTo("SUCCEEDED");
        }
        uploadWithRecord(check("b"), map("error", "L3 run failed"), recordOf(record), a);
        uploadWithRecord(prCheck("c"), plain, recordOf(record), a);
        assertThat(recordScans()).containsExactly(scan);
    }

    @Test
    void recordsAreKeptForRecentImagesAndTheRunningOne() {
        var a = item("a", "CVE-2026-1", "HIGH", "UNREACHABLE", "CALLGRAPH", null, List.of(map("kind", "NOTE", "summary", "x")));
        var result = l3(l3Cve("CVE-2026-1", "a", "NONE", true, false));
        observe("1");   // 이미지 1이 운영에서 실행 중
        var scans = new java.util.ArrayList<Long>();
        for (String image : List.of("1", "2", "3", "4", "5", "6", "7")) {
            scans.add(uploadWithRecord(check(image), result, recordOf(xz(image)), a));
        }
        // 최근 5개(3~7)와 실행 중인 1이 남고 2는 정리된다
        assertThat(recordScans()).containsExactly(scans.get(0), scans.get(2), scans.get(3), scans.get(4), scans.get(5), scans.get(6));
        // 같은 이미지를 다시 띄워 보면 그 이미지의 새 기록만 남는다
        long again = uploadWithRecord(check("7"), result, recordOf(xz("7b")), a);
        assertThat(recordScans()).containsExactly(scans.get(0), scans.get(2), scans.get(3), scans.get(4), scans.get(5), again);
        // 결과는 기록이 정리돼도 남는다
        assertThat(jdbc.queryForObject("SELECT count(*) FROM reach_l3_results", Long.class)).isEqualTo(7);
    }

    @Test
    void prScansTakeNoL3() {
        var a = item("a", "CVE-2026-1", "HIGH", "UNREACHABLE", "CALLGRAPH", null, List.of(map("kind", "NOTE", "summary", "x")));
        uploadWithL3(prCheck("a"), l3(l3Cve("CVE-2026-1", "a", "REGION", true, false)), a);
        assertThat(jdbc.queryForObject("SELECT (SELECT count(*) FROM reach_l3_runs) + (SELECT count(*) FROM reach_l3_results)",
                Long.class)).isZero();
    }

    @Test
    void l3ResultsAreMatchedByPackageCoordinates() {
        assertThat(ReachL3Input.coordinates("pkg:maven/org.bouncycastle/bcprov-jdk18on@1.81?type=jar")).isEqualTo("org.bouncycastle:bcprov-jdk18on");
        assertThat(ReachL3Input.coordinates("pkg:maven/tools.jackson.core/jackson-core@3.1.5")).isEqualTo("tools.jackson.core:jackson-core");
        assertThat(ReachL3Input.coordinates("pkg:npm/%40scope/name@1.0.0")).isEqualTo("@scope:name");
        assertThat(ReachL3Input.coordinates("pkg:npm/left-pad@1.0.0")).isEqualTo("left-pad");
        assertThat(ReachL3Input.coordinates("not a purl")).isEmpty();
    }

    @Test
    void serverErrorRollsBackTheResultsAndLeavesTheScanFailed() {
        var broken = new ReachResultRepository(JdbcClient.create(jdbc)) {
            @Override
            void succeedScan(long scanId) {
                throw new IllegalStateException("boom");
            }
        };
        service = new ReachResultService(broken, l1, manager);
        long check = check("a");
        byte[] body = gzip(bundle(List.of(item("a", "CVE-2026-1", "HIGH", "REACHABLE", "CALLGRAPH", null, List.of()))));
        assertThatThrownBy(() -> service.upload("admin", check, "gzip", body)).isInstanceOf(IllegalStateException.class);

        assertThat(jdbc.queryForObject("SELECT count(*) FROM reach_findings", Long.class)).isZero();
        assertThat(jdbc.queryForMap("SELECT s.scan_status, s.failure_code, s.failure_stage FROM reach_scans s "
                + "JOIN reach_ci_checks c ON c.scan_id = s.scan_id WHERE c.check_id = ?", check))
                .containsEntry("scan_status", "FAILED").containsEntry("failure_code", "INTERNAL_ERROR")
                .containsEntry("failure_stage", "REPORT");
        assertError(() -> service.upload("admin", check, "gzip", body), ErrorCode.CONFLICT);
    }

    /** 지금 시각의 L1 조회. check(tag)의 digest를 돌리는 워크로드 하나만 있다 */
    private static void observe(String tag) {
        jdbc.update("INSERT INTO reach_workload_observations (cluster, namespace, observed_at, source, reported_by) "
                + "VALUES ('reused-prod', 'reused', clock_timestamp(), 'MANUAL', 'USER:1') ON CONFLICT (cluster, namespace) "
                + "DO UPDATE SET observed_at = EXCLUDED.observed_at");
        jdbc.update("DELETE FROM reach_workloads");
        jdbc.update("INSERT INTO reach_workloads (cluster, namespace, kind, name, container, image, image_digest, ready_replicas) "
                + "VALUES ('reused-prod', 'reused', 'Deployment', 'reused-api', 'api', 'r/api:x', ?, 1)", "sha256:" + tag.repeat(64));
    }

    private static String deployment(long findingId) {
        return jdbc.queryForObject("SELECT deployment FROM reach_findings WHERE finding_id = ?", String.class, findingId);
    }

    /** 이미지 digest가 다르면 대상이 다르다. 같은 tag면 같은 대상의 새 스캔이다 */
    private long check(String tag) {
        var target = new ReachTargetRequest("IMAGE", null, null,
                new ReachTargetRequest.Image("logssey/reused-api", "sha256:" + tag.repeat(64)));
        var request = new ReachCiCheckRequest("IMAGE_BUILD", "service-backend", null, null, target, null, null, null);
        return checks.create("admin", "key-" + System.nanoTime(), request).check().id();
    }

    /** PR 검사. service-backend 레포라 app이 API로 정해져 check()의 이미지와 같은 서비스다 */
    private long prCheck(String tag) {
        return repoCheck("PR", tag);
    }

    /** 레포 대상 검사. 같은 tag면 같은 커밋이라 같은 대상이다. PR이면 pullRequest를 붙인다 */
    private long repoCheck(String mode, String tag) {
        String commit = tag.repeat(40);
        var target = new ReachTargetRequest("REPO", null, new ReachTargetRequest.Repo("service-backend", commit, null), null);
        var pullRequest = "PR".equals(mode) ? new ReachCiCheckRequest.PullRequest(1, "main", "feature/x") : null;
        var request = new ReachCiCheckRequest(mode, "service-backend", commit, pullRequest, target, null, null, null);
        return checks.create("admin", "key-" + System.nanoTime(), request).check().id();
    }

    /** 올린 뒤 스캔 id */
    @SafeVarargs
    private long upload(long check, Map<String, Object>... items) {
        return service.upload("admin", check, "gzip", gzip(bundle(List.of(items)))).scanId();
    }

    /** l3를 붙여 올린 뒤 스캔 id */
    @SafeVarargs
    private long uploadWithL3(long check, Object l3, Map<String, Object>... items) {
        var bundle = bundle(List.of(items));
        bundle.put("l3", l3);
        return service.upload("admin", check, "gzip", gzip(bundle)).scanId();
    }

    /** l3와 실행 기록(l3Record)을 붙여 올린 뒤 스캔 id */
    @SafeVarargs
    private long uploadWithRecord(long check, Object l3, Object record, Map<String, Object>... items) {
        var bundle = bundle(List.of(items));
        bundle.put("l3", l3);
        bundle.put("l3Record", record);
        return service.upload("admin", check, "gzip", gzip(bundle)).scanId();
    }

    private static Map<String, Object> recordOf(byte[] content) {
        return map("format", "TAR_XZ", "content", java.util.Base64.getEncoder().encodeToString(content));
    }

    /** xz 머리 바이트로 시작하는 임의 내용. 서버는 묶음을 풀지 않고 그대로 보관한다 */
    private static byte[] xz(String tag) {
        byte[] body = ("record-" + tag).getBytes();
        byte[] out = new byte[6 + body.length];
        System.arraycopy(new byte[] {(byte) 0xFD, '7', 'z', 'X', 'Z', 0}, 0, out, 0, 6);
        System.arraycopy(body, 0, out, 6, body.length);
        return out;
    }

    private static byte[] sha256(byte[] value) {
        try {
            return java.security.MessageDigest.getInstance("SHA-256").digest(value);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static List<Long> recordScans() {
        return jdbc.queryForList("SELECT scan_id FROM reach_l3_records ORDER BY scan_id", Long.class);
    }

    /** 러너 verdict/l3.py 출력 + run (l3-run.sh). secretValue는 서버가 모르는 칸이다 */
    @SafeVarargs
    private static Map<String, Object> l3(Map<String, Object>... cves) {
        return map("tool", "reach-l3 0.2.0", "scope", "java.util.*:org.*", "segments", List.of("startup", "001", "002"),
                "counts", map("REGION", 1, "FUNCTION", 1, "NONE", 0, "NOT_RECORDED", 0), "cves", List.of(cves),
                "run", map("observationMethod", "coverage", "observedAt", "2026-11-18T13:01:58Z", "scenario", "2026-11-18.1",
                        "build", map("imageDigest", "sha256:abc"),
                        "configKeys", List.of(map("name", "KAKAO_STUB", "enabled", true)),
                        "invocations", List.of(map("segment", "001", "name", "categories", "request", "GET /api/v1/categories",
                                        "count", 1, "ok", 1, "failed", 0, "skipped", 0),
                                map("segment", "002", "name", "create", "request", "POST /items", "count", 1, "ok", 1,
                                        "failed", 0, "skipped", 0)),
                        "requests", map("count", 2, "ok", 2, "failed", 0, "skipped", 0), "scope", "java.util.*:org.*",
                        "javaRelease", 21, "secretValue", "must not be stored"));
    }

    /** CVE 하나의 L3 결과. item()의 purl(pkg:maven/test/<component>@1)에 맞춘 좌표 */
    private static Map<String, Object> l3Cve(String cve, String component, String reached, boolean regionsChecked,
                                             boolean startupOnly) {
        return map("cve", cve, "coordinates", "test:" + component, "reached", reached, "during", List.of("002"),
                "startupOnly", startupOnly, "installedVersions", List.of("1"), "regionVersion", "1",
                "regionsChecked", regionsChecked,
                "regions", List.of(map("class", "org.example.Parser", "method", "check", "lines", List.of(List.of(626, 627)),
                        "executedLines", List.of(626, 627), "executed", true, "during", List.of("002"))),
                "functions", List.of(map("function", "org.example.Parser#check", "during", List.of("001", "002"))));
    }

    /** component:reached:scan (Finding의 지금 L3 결과) */
    private static List<String> l3Results() {
        return jdbc.queryForList("SELECT f.component_name || ':' || x.reached || ':' || x.scan_id FROM reach_l3_results x "
                + "JOIN reach_findings f ON f.finding_id = x.finding_id ORDER BY 1", String.class);
    }

    /** API-06으로 사람이 확정한다 (base_verdict_id·MANUAL·이력을 실제 API처럼 남긴다) */
    private void confirm(long findingId, String status, int version) {
        reviews.save("admin", findingId, new ReachReviewRequest("CONFIRMED", status, "checked", null, version));
    }

    private static long finding(String component) {
        return jdbc.queryForObject("SELECT min(finding_id) FROM reach_findings WHERE component_name = ?", Long.class, component);
    }

    private static long currentVerdict(long findingId) {
        return jdbc.queryForObject("SELECT verdict_id FROM reach_verdicts WHERE finding_id = ? AND is_current", Long.class, findingId);
    }

    private static String scanStatus(long checkId) {
        return jdbc.queryForObject("SELECT s.scan_status FROM reach_scans s JOIN reach_ci_checks c ON c.scan_id = s.scan_id "
                + "WHERE c.check_id = ?", String.class, checkId);
    }

    private static String review(long findingId) {
        return jdbc.queryForObject("SELECT review_state || ':' || version || ':' || COALESCE(reset_reason, 'null') "
                + "FROM reach_reviews WHERE finding_id = ?", String.class, findingId);
    }

    private static List<String> history(long findingId) {
        return jdbc.queryForList("SELECT version || ':' || change_kind || ':' || review_state "
                + "FROM reach_review_history WHERE finding_id = ? ORDER BY version", String.class, findingId);
    }

    /** 러너가 올리는 묶음. sbom은 보관만 하고 matches·reachResult는 저장하지 않아 모양만 맞춘다 */
    private static Map<String, Object> bundle(List<Map<String, Object>> items) {
        return map("sbom", map("bomFormat", "CycloneDX", "components",
                        List.of(map("name", "jackson-core"), map("name", "zlib"))), "matches", map("trivy", map()), "verdicts", items,
                "reachResult", map("facts", List.of()), "tools", map("trivy", "0.69.3", "reach", "v0"),
                "analysis", map("appClasses", 412),
                "stages", List.of(map("name", "sbom", "status", "succeeded", "durationSeconds", 8),
                        map("name", "L2", "status", "SUCCEEDED", "durationSeconds", 41)));
    }

    /** Finding 한 항목. purl은 component 이름으로 만든다 */
    private static Map<String, Object> item(String component, String cve, String severity, String status, String method,
                                            String reason, List<Map<String, Object>> evidence) {
        return map("component", map("purl", "pkg:maven/test/" + component + "@1", "name", component, "version", "1"),
                "vulnerability", map("id", cve, "severity", severity, "fixedVersions", List.of("1.0.1")),
                "sources", List.of("trivy"),
                "verdict", map("status", status, "method", method, "notAnalyzedReason", reason, "summary", "test",
                        "evidence", evidence, "engine", map("reach", "v0", "rulesVersion", "1.0.0")));
    }

    private static Map<String, Object> withCallgraph(Map<String, Object> verdict) {
        verdict.put("callgraph", map("packageReached", true, "vulnFunctionReached", true, "entryStage", 1));
        return verdict;
    }

    /** null 값을 넣을 수 있는 순서 있는 Map. Map.of는 null을 받지 않는다 */
    private static Map<String, Object> map(Object... keyValues) {
        var map = new LinkedHashMap<String, Object>();
        for (int i = 0; i < keyValues.length; i += 2) map.put((String) keyValues[i], keyValues[i + 1]);
        return map;
    }

    private static byte[] gzip(Object json) {
        return gzip(json instanceof String s ? s.getBytes() : MAPPER.writeValueAsBytes(json));
    }

    private static byte[] gzip(byte[] raw) {
        var out = new ByteArrayOutputStream();
        try (var zip = new GZIPOutputStream(out)) {
            zip.write(raw);
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
        return out.toByteArray();
    }

    private static void assertError(Runnable call, ErrorCode code) {
        assertThatThrownBy(call::run).isInstanceOfSatisfying(ApiException.class,
                e -> assertThat(e.errorCode()).isEqualTo(code));
    }
}
