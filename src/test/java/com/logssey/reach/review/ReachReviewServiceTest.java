package com.logssey.reach.review;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

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

class ReachReviewServiceTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static JdbcTemplate jdbc;
    private ReachReviewService service;
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
        scan = scan(target("sha256:a"));
        service = new ReachReviewService(new ReachReviewRepository(JdbcClient.create(jdbc)));
    }

    @Test
    void requiresAdmin() {
        long id = finding("CVE-2026-1", "UNREACHABLE");
        assertError(() -> service.save(null, id, confirm("UNREACHABLE", 1)), ErrorCode.UNAUTHENTICATED);
        assertError(() -> service.save("nobody", id, confirm("UNREACHABLE", 1)), ErrorCode.FORBIDDEN);
    }

    @Test
    void confirmsAToolVerdictWithoutChangingIt() {
        long id = finding("CVE-2026-1", "UNREACHABLE");

        var review = service.save("admin", id, confirm("UNREACHABLE", 1));

        assertThat(review.reviewState()).isEqualTo("CONFIRMED");
        assertThat(review.version()).isEqualTo(2);
        assertThat(review.reviewer().name()).isEqualTo("Admin");
        assertThat(review.reviewedAt()).isNotNull();
        assertThat(review.disagreesWithTool()).isFalse();
        assertThat(currentVerdict(id)).containsEntry("status", "UNREACHABLE").containsEntry("method", "CALLGRAPH");
        assertThat(jdbc.queryForList("SELECT version, change_kind FROM reach_review_history WHERE finding_id = ?", id))
                .containsExactly(Map.of("version", 2, "change_kind", "HUMAN"));
    }

    @Test
    void disagreementKeepsTheToolVerdict() {
        long id = finding("CVE-2026-1", "UNREACHABLE");

        var review = service.save("admin", id, confirm("REACHABLE", 1));

        assertThat(review.status()).isEqualTo("REACHABLE");
        assertThat(review.disagreesWithTool()).isTrue();                     // 다시 볼 대상 (FR-08)
        assertThat(currentVerdict(id)).containsEntry("status", "UNREACHABLE");  // 도구 판정은 바꾸지 않는다 (NFR-04)
    }

    @Test
    void staleVersionIsAConflict() {
        long id = finding("CVE-2026-1", "UNREACHABLE");
        assertError(() -> service.save("admin", id, confirm("UNREACHABLE", 5)), ErrorCode.CONFLICT);

        service.save("admin", id, confirm("UNREACHABLE", 1));
        // 같은 본문을 다시 보내면 version이 이미 올라가 있다 (API 명세 2-7)
        assertError(() -> service.save("admin", id, confirm("UNREACHABLE", 1)), ErrorCode.CONFLICT);
    }

    @Test
    void humanStatusBecomesTheVerdictOfANotAnalyzedFinding() {
        long id = finding("CVE-2026-1", "NOT_ANALYZED");
        long toolVerdict = currentVerdictId(id);

        var review = service.save("admin", id, confirm("UNREACHABLE", 1));

        assertThat(currentVerdict(id)).containsEntry("status", "UNREACHABLE").containsEntry("method", "MANUAL")
                .containsEntry("created_by_user_id", 1L);
        assertThat(currentVerdictId(id)).isNotEqualTo(toolVerdict);
        assertThat(review.disagreesWithTool()).isFalse();
    }

    @Test
    void unreviewedRestoresTheToolVerdict() {
        long id = finding("CVE-2026-1", "NOT_ANALYZED");
        long toolVerdict = currentVerdictId(id);
        service.save("admin", id, confirm("UNREACHABLE", 1));

        var review = service.save("admin", id, new ReachReviewRequest("UNREVIEWED", null, null, null, 2));

        assertThat(currentVerdictId(id)).isEqualTo(toolVerdict);
        assertThat(currentVerdict(id)).containsEntry("status", "NOT_ANALYZED");
        assertThat(review.status()).isNull();
        assertThat(review.note()).isNull();
        // MANUAL 판정은 판정 이력으로, 두 번의 저장은 검토 이력으로 남는다
        assertThat(jdbc.queryForObject("SELECT count(*) FROM reach_verdicts WHERE finding_id = ?", Long.class, id)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM reach_review_history WHERE finding_id = ?", Long.class, id)).isEqualTo(2);
    }

    @Test
    void theBaseIsTheToolVerdictOnScreenNotALaterPullRequestVerdict() {
        long id = finding("CVE-2026-1", "REACHABLE");
        long shown = currentVerdictId(id);
        // a PR check of the same commit leaves its own verdict on this finding (ARD SR-09) with a later analyzedAt
        long pr = prVerdict(id, "UNREACHABLE", "CALLGRAPH", "now() + interval '1 hour'");

        service.save("admin", id, confirm("REACHABLE", 1));
        assertThat(jdbc.queryForObject("SELECT base_verdict_id FROM reach_reviews WHERE finding_id = ?", Long.class, id))
                .isEqualTo(shown).isNotEqualTo(pr);
    }

    @Test
    void unreviewedNeverRestoresAPullRequestVerdict() {
        long id = finding("CVE-2026-1", "NOT_ANALYZED");
        long tool = currentVerdictId(id);
        service.save("admin", id, confirm("UNREACHABLE", 1));   // MANUAL becomes current
        prVerdict(id, "NOT_ANALYZED", null, "now() + interval '1 hour'");

        service.save("admin", id, new ReachReviewRequest("UNREVIEWED", null, null, null, 2));
        assertThat(currentVerdictId(id)).isEqualTo(tool);
    }

    /** 같은 Finding에 PR 검사 스캔이 남긴 도구 판정 */
    private static long prVerdict(long findingId, String status, String method, String analyzedAt) {
        long prScan = jdbc.queryForObject("""
                INSERT INTO reach_scans (target_id, scan_status, trigger_type, requested_by_kind, finished_at)
                SELECT target_id, 'SUCCEEDED', 'PR', 'SYSTEM', now() FROM reach_findings WHERE finding_id = ? RETURNING scan_id
                """, Long.class, findingId);
        return jdbc.queryForObject("""
                INSERT INTO reach_verdicts (finding_id, scan_id, status, method, not_analyzed_reason, summary,
                                            engine, evidence_hash, is_current, analyzed_at)
                VALUES (?, ?, ?, ?, ?, 'pr', '{}', 'h2', false, %s) RETURNING verdict_id
                """.formatted(analyzedAt), Long.class, findingId, prScan, status, method,
                method == null ? "UNANALYZED_COPY" : null);
    }

    @Test
    void proposalIsOnlyKeptWhileUnreviewed() {
        long id = finding("CVE-2026-89407", "NOT_ANALYZED");
        var proposal = new ReachReviewRequest.Proposal("UNREACHABLE", "발동 조건 없음", "규칙명세서 9-1");

        var proposed = service.save("admin", id, new ReachReviewRequest("UNREVIEWED", null, null, proposal, 1));
        assertThat(proposed.reviewState()).isEqualTo("UNREVIEWED");
        assertThat(proposed.proposal().get("summary").asString()).isEqualTo("발동 조건 없음");
        assertThat(currentVerdict(id)).containsEntry("status", "NOT_ANALYZED");   // 제안은 판정을 바꾸지 않는다

        assertError(() -> service.save("admin", id, new ReachReviewRequest("CONFIRMED", "UNREACHABLE", "ok", proposal, 2)),
                ErrorCode.INVALID_INPUT);

        var confirmed = service.save("admin", id, confirm("UNREACHABLE", 2));
        assertThat(confirmed.proposal()).isNull();                            // 확정하면 현재 값에서 빠지고 이력에만 남는다
        assertThat(jdbc.queryForObject("SELECT count(*) FROM reach_review_history WHERE finding_id = ? AND proposal IS NOT NULL",
                Long.class, id)).isEqualTo(1);
    }

    @Test
    void rejectsInvalidBodies() {
        long id = finding("CVE-2026-1", "UNREACHABLE");
        assertError(() -> service.save("admin", id, new ReachReviewRequest("CONFIRMED", "UNREACHABLE", null, null, 1)), ErrorCode.INVALID_INPUT);
        assertError(() -> service.save("admin", id, new ReachReviewRequest("CONFIRMED", "UNREACHABLE", " ", null, 1)), ErrorCode.INVALID_INPUT);
        assertError(() -> service.save("admin", id, new ReachReviewRequest("CONFIRMED", "UNREACHABLE", "x".repeat(2001), null, 1)), ErrorCode.INVALID_INPUT);
        assertError(() -> service.save("admin", id, new ReachReviewRequest("CONFIRMED", "NOT_ANALYZED", "note", null, 1)), ErrorCode.INVALID_INPUT);
        assertError(() -> service.save("admin", id, new ReachReviewRequest("CONFIRMED", null, "note", null, 1)), ErrorCode.INVALID_INPUT);
        assertError(() -> service.save("admin", id, new ReachReviewRequest("CONFIRMED", "UNREACHABLE", "note", null, null)), ErrorCode.INVALID_INPUT);
        assertError(() -> service.save("admin", id, new ReachReviewRequest(null, null, null, null, 1)), ErrorCode.INVALID_INPUT);
        assertError(() -> service.save("admin", id, new ReachReviewRequest("DONE", null, null, null, 1)), ErrorCode.INVALID_INPUT);
        assertError(() -> service.save("admin", id, new ReachReviewRequest("UNREVIEWED", "UNREACHABLE", null, null, 1)), ErrorCode.INVALID_INPUT);
        assertError(() -> service.save("admin", id, new ReachReviewRequest("UNREVIEWED", null, null,
                new ReachReviewRequest.Proposal("NOT_ANALYZED", "x", null), 1)), ErrorCode.INVALID_INPUT);

        // 2,000자는 글자 수로 센다. 이모지 2,000개는 Java length()로 4,000이지만 받는다
        var emoji = service.save("admin", id, new ReachReviewRequest("PROVISIONAL", "UNREACHABLE", "😀".repeat(2000), null, 1));
        assertThat(emoji.reviewState()).isEqualTo("PROVISIONAL");
    }

    @Test
    void missingFindingAndResetReason() {
        assertError(() -> service.save("admin", 999, confirm("UNREACHABLE", 1)), ErrorCode.NOT_FOUND);

        long id = finding("CVE-2026-1", "UNREACHABLE");
        jdbc.update("UPDATE reach_reviews SET reset_reason = 'VERDICT_CHANGED' WHERE finding_id = ?", id);
        var review = service.save("admin", id, confirm("UNREACHABLE", 1));
        assertThat(review.resetReason()).isNull();                            // 사람이 다시 기록하면 빈다 (3-10)
    }

    private static ReachReviewRequest confirm(String status, int version) {
        return new ReachReviewRequest("CONFIRMED", status, "checked", null, version);
    }

    private static void assertError(org.assertj.core.api.ThrowableAssert.ThrowingCallable call, ErrorCode code) {
        assertThatThrownBy(call).satisfies(e -> assertThat(((ApiException) e).errorCode()).isEqualTo(code));
    }

    private static Map<String, Object> currentVerdict(long findingId) {
        return jdbc.queryForMap("SELECT status, method, created_by_user_id FROM reach_verdicts WHERE finding_id = ? AND is_current",
                findingId);
    }

    private static long currentVerdictId(long findingId) {
        return jdbc.queryForObject("SELECT verdict_id FROM reach_verdicts WHERE finding_id = ? AND is_current", Long.class, findingId);
    }

    private static long target(String digest) {
        return jdbc.queryForObject("""
                INSERT INTO reach_targets (target_type, app, image_repository, image_digest, display_name)
                VALUES ('IMAGE', 'API', 'reused-api', ?, 'api') RETURNING target_id
                """, Long.class, digest);
    }

    private static long scan(long targetId) {
        return jdbc.queryForObject("""
                INSERT INTO reach_scans (target_id, scan_status, trigger_type, requested_by_kind, finished_at)
                VALUES (?, 'SUCCEEDED', 'MANUAL', 'SYSTEM', now()) RETURNING scan_id
                """, Long.class, targetId);
    }

    /** 검토 전(UNREVIEWED, version 1) Finding + 도구 판정. NOT_ANALYZED면 방식 없이 사유 UNANALYZED_COPY */
    private long finding(String cve, String status) {
        long id = jdbc.queryForObject("""
                INSERT INTO reach_findings (target_id, purl, component_name, component_version, ecosystem,
                                            vulnerability_id, severity, sources, last_scan_id, first_seen_at, last_seen_at)
                SELECT target_id, 'pkg:maven/test/lib@1', 'lib', '1', 'maven', ?, 'HIGH', ARRAY['TRIVY'], scan_id, now(), now()
                FROM reach_scans WHERE scan_id = ? RETURNING finding_id
                """, Long.class, cve, scan);
        boolean notAnalyzed = status.equals("NOT_ANALYZED");
        jdbc.update("""
                INSERT INTO reach_verdicts (finding_id, scan_id, status, method, not_analyzed_reason, summary,
                                            engine, evidence_hash, is_current, analyzed_at)
                VALUES (?, ?, ?, ?, ?, 'tool', '{}', 'h', true, now() - interval '1 hour')
                """, id, scan, status, notAnalyzed ? null : "CALLGRAPH", notAnalyzed ? "UNANALYZED_COPY" : null);
        jdbc.update("INSERT INTO reach_reviews (finding_id) VALUES (?)", id);
        return id;
    }
}
