package com.logssey.reach.report;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.OffsetDateTime;
import java.util.List;

import com.logssey.reach.query.ReachQueryRepository.ReportRow;
import com.logssey.reach.query.ReachQueryService;
import com.logssey.reach.rule.ReachVulnFunctionData;
import com.logssey.report.ReportChapter;
import com.logssey.report.ReportFinding;

import org.junit.jupiter.api.Test;

class ReachReportChapterProviderTest {

    private static final OffsetDateTime FIRST = OffsetDateTime.parse("2026-11-01T04:30:00+09:00");
    private static final OffsetDateTime SCANNED = OffsetDateTime.parse("2026-11-23T04:30:00+09:00");
    private static final OffsetDateTime FROM = OffsetDateTime.parse("2026-10-24T00:00:00+09:00");
    private static final OffsetDateTime TO = OffsetDateTime.parse("2026-11-24T00:00:00+09:00");

    private static ReportRow row(long id, String cve, String severity, String status, String method, String reviewState,
                                 String reviewStatus) {
        return new ReportRow(id, "API", "reused-api @ 1a2b3c4d", true, SCANNED, cve, severity, "tomcat-embed-core",
                "11.0.24", "app.jar/BOOT-INF/lib/tomcat-embed-core-11.0.24.jar", "Tomcat title", "HTTP/2 헤더 처리",
                List.of("9.0.122", "10.1.60", "11.0.26"), status, method,
                "HTTP/2를 켜는 설정이나 코드가 없다.", "NOT_ANALYZED".equals(status) ? "NO_VULN_FUNCTION_DATA" : null,
                reviewState, reviewStatus, null, false, FIRST);
    }

    private static ReachQueryService.ReportScope scope(ReportRow... rows) {
        return new ReachQueryService.ReportScope("RUNNING", List.of(rows), 0, List.of());
    }

    @Test
    void 도달_불가는_목록에서_빼고_보류로_센다() {
        var chapter = ReachReportChapterProvider.chapter(scope(
                row(1, "CVE-2026-1", "CRITICAL", "REACHABLE", "CALLGRAPH", "UNREVIEWED", null),
                row(2, "CVE-2026-2", "HIGH", "UNKNOWN", "RULE", "UNREVIEWED", null),
                row(3, "CVE-2026-3", "CRITICAL", "UNREACHABLE", "RULE", "UNREVIEWED", null),
                row(4, "CVE-2026-4", "HIGH", "UNREACHABLE", "RULE", "CONFIRMED", "UNREACHABLE"),
                row(5, "CVE-2026-5", "UNKNOWN", "NOT_ANALYZED", null, "UNREVIEWED", null)), FROM, TO);

        assertThat(chapter.findings()).extracting(ReportFinding::id).containsExactly("REACH-F1", "REACH-F2", "REACH-F5");
        assertThat(chapter.keyMetric().value()).isEqualTo(1);
        assertThat(chapter.headline()).isEqualTo("운영 이미지에서 도달 가능 Critical·High 1건 · 확인 못 함 1건 (도달 불가 2건 보류)");
        assertThat(chapter.severityCounts()).containsEntry("CRITICAL", 1L).containsEntry("HIGH", 1L)
                .containsEntry("UNASSESSED", 1L);
        assertThat(chapter.scope()).anySatisfy(item -> {
            assertThat(item.label()).isEqualTo("도달 불가로 보류");
            assertThat(item.value()).isEqualTo("2건 = 사람 확정 1 · 검토 전 1 (Critical 1 · High 1)");
        });
        assertThat(chapter.newInPeriod()).isEqualTo(3);
        assertThat(chapter.resolvedInPeriod()).as("해결 건수는 아직 세지 않는다").isNull();
        assertThat(chapter.dataAsOf()).isEqualTo(SCANNED);
    }

    @Test
    void 사람_확정이_도구_판정을_이기고_잠정은_위험한_쪽을_쓴다() {
        var confirmed = row(1, "CVE-2026-1", "HIGH", "UNREACHABLE", "RULE", "CONFIRMED", "REACHABLE");
        var provisional = row(2, "CVE-2026-2", "HIGH", "UNREACHABLE", "RULE", "PROVISIONAL", "UNKNOWN");
        var saferProvisional = row(3, "CVE-2026-3", "HIGH", "REACHABLE", "CALLGRAPH", "PROVISIONAL", "UNREACHABLE");

        assertThat(ReachReportChapterProvider.effective(confirmed)).isEqualTo("REACHABLE");
        assertThat(ReachReportChapterProvider.effective(provisional)).isEqualTo("UNKNOWN");
        assertThat(ReachReportChapterProvider.effective(saferProvisional)).isEqualTo("REACHABLE");
        var finding = ReachReportChapterProvider.finding(confirmed, "REACHABLE", "HIGH", "x");
        assertThat(finding.response()).isEqualTo("미조치 · 도달 가능 (사람 확정)");
        assertThat(finding.evidence()).startsWith("사람 확정: 도달 가능");
    }

    @Test
    void 같은_앱_패키지_CVE는_한_건이다() {
        var running = row(1, "CVE-2026-1", "CRITICAL", "REACHABLE", "CALLGRAPH", "UNREVIEWED", null);
        var otherDigest = row(2, "CVE-2026-1", "CRITICAL", "REACHABLE", "CALLGRAPH", "UNREVIEWED", null);

        assertThat(ReachReportChapterProvider.chapter(scope(running, otherDigest), FROM, TO).findings()).hasSize(1);
    }

    private static ReportRow pkg(long id, String cve, String name, String version, String status, String... fixed) {
        return new ReportRow(id, "API", "reused-api @ 1a2b3c4d", true, SCANNED, cve, "HIGH", name, version, null, null,
                null, List.of(fixed), status, "NOT_ANALYZED".equals(status) ? null : "RULE", null,
                "NOT_ANALYZED".equals(status) ? "UNANALYZED_COPY" : null, "UNREVIEWED", null, null, false, FIRST);
    }

    @Test
    void 이름이_같아도_버전이_다르면_다른_건이다() {
        // 실제 Re:Used api: jackson-databind 2.21.5(사본, 판정 전)와 3.1.5(도달 불가)가 같은 CVE로 잡힌다
        var copy = pkg(1, "CVE-2026-91776", "jackson-databind", "2.21.5", "NOT_ANALYZED", "2.21.7", "3.1.6");
        var judged = pkg(2, "CVE-2026-91776", "jackson-databind", "3.1.5", "UNREACHABLE", "2.21.7", "3.1.6");

        var chapter = ReachReportChapterProvider.chapter(scope(copy, judged), FROM, TO);
        assertThat(chapter.findings()).extracting(ReportFinding::id).containsExactly("REACH-F1");
        assertThat(chapter.headline()).endsWith("(도달 불가 1건 보류)");
    }

    @Test
    void 판정_전_사본은_사유를_근거에만_쓰고_제목은_같은_CVE의_한국어_요약을_쓴다() {
        // 실제 Re:Used api: Jackson 2 사본에는 스캐너 영어 제목만 있다. 판정 데이터(Jackson 3 쪽)의 한국어 요약을 쓴다
        var data = new ReachVulnFunctionData();   // 실제 동봉 파일
        String summary = data.summaryKo("CVE-2026-91776");
        assertThat(summary).isNotBlank();
        var copy = new ReportRow(1, "API", "reused-api @ 1a2b3c4d", true, SCANNED, "CVE-2026-91776", "HIGH",
                "jackson-databind", "2.21.5", null, "Denial of Service via unbounded cache growth", null, List.of("2.21.7"),
                "NOT_ANALYZED", null, null, "UNANALYZED_COPY", "UNREVIEWED", null, null, false, FIRST);

        var finding = ReachReportChapterProvider.chapter(scope(copy), FROM, TO, data::summaryKo).findings().get(0);
        assertThat(finding.title()).startsWith("CVE-2026-91776 · jackson-databind 2.21.5: " + summary.substring(0, 20))
                .doesNotContain("Denial of Service");
        assertThat(finding.response()).isEqualTo("미조치 · 판정 전");
        assertThat(finding.evidence())
                .isEqualTo("판정 전: 같은 CVE의 판정 데이터가 다른 패키지에만 있어 이 패키지는 아직 판정하지 않음");

        // 판정 데이터에 없는 CVE는 스캐너 제목 그대로
        var unknownCve = ReachReportChapterProvider.finding(copy, "NOT_ANALYZED", "HIGH", "x", data.summaryKo("CVE-2026-1"));
        assertThat(unknownCve.title()).endsWith(": Denial of Service via unbounded cache growth");
    }

    @Test
    void 한_패키지의_조치는_보류_건까지_고치는_가장_높은_수정_버전_하나로_묶는다() {
        // 실제 Re:Used api: 넣는 건은 11.0.26이면 되지만 보류한 Critical 3건은 11.0.27에서 고쳐진다
        var a = pkg(1, "CVE-2026-1", "tomcat-embed-core", "11.0.24", "UNKNOWN", "10.1.59", "11.0.25");
        var b = pkg(2, "CVE-2026-2", "tomcat-embed-core", "11.0.24", "NOT_ANALYZED", "10.1.60", "11.0.26");
        var held = pkg(3, "CVE-2026-3", "tomcat-embed-core", "11.0.24", "UNREACHABLE", "10.1.61", "11.0.27");
        var noFix = pkg(4, "CVE-2026-4", "tomcat-embed-core", "11.0.24", "UNKNOWN");

        var chapter = ReachReportChapterProvider.chapter(scope(a, b, held, noFix), FROM, TO);
        assertThat(chapter.remediations()).extracting(ReportChapter.Remediation::title)
                .containsExactlyInAnyOrder("Tomcat 11.0.27 이상으로 올리기", "tomcat-embed-core 수정 버전 없음: 완화책 검토");
        assertThat(chapter.findings()).extracting(ReportFinding::action).containsExactly(
                "Tomcat 11.0.27 이상으로 올리기", "Tomcat 11.0.27 이상으로 올리기",
                "tomcat-embed-core 수정 버전 없음: 완화책 검토");
        assertThat(chapter.remediations()).anySatisfy(r -> {
            assertThat(r.impact()).isEqualTo("Critical 0 · High 2 · 그 밖 0건 (API) · 도달 불가로 보류한 1건도 함께 해소");
            assertThat(r.how()).contains("tomcat.version");
        });
        assertThat(chapter.scope()).anySatisfy(item -> assertThat(item.value()).isEqualTo("없음"));
    }

    @Test
    void Spring_Boot_속성_하나로_같이_올라가는_jar는_조치_하나다() {
        var core = pkg(1, "CVE-2026-1", "tomcat-embed-core", "11.0.24", "UNKNOWN", "11.0.26");
        var websocketHeld = pkg(2, "CVE-2026-2", "tomcat-embed-websocket", "11.0.24", "UNREACHABLE", "11.0.27");
        var jacksonCore = pkg(3, "CVE-2026-3", "jackson-core", "2.21.5", "NOT_ANALYZED", "2.21.7");
        var jacksonDatabind = pkg(4, "CVE-2026-4", "jackson-databind", "2.21.5", "NOT_ANALYZED", "2.21.6");

        var chapter = ReachReportChapterProvider.chapter(scope(core, websocketHeld, jacksonCore, jacksonDatabind), FROM, TO);
        assertThat(chapter.remediations()).extracting(ReportChapter.Remediation::title)
                .containsExactlyInAnyOrder("Tomcat 11.0.27 이상으로 올리기", "Jackson 2.21.7 이상으로 올리기");
        assertThat(chapter.remediations()).anySatisfy(r -> {
            assertThat(r.title()).startsWith("Tomcat");
            assertThat(r.impact()).endsWith("도달 불가로 보류한 1건도 함께 해소");
        });
        assertThat(chapter.scope()).anySatisfy(item -> {
            assertThat(item.label()).startsWith("보류 건만 있는 패키지");
            assertThat(item.value()).isEqualTo("없음");
        });
    }

    @Test
    void 보류_건만_있는_패키지는_범위_표에_올릴_버전과_함께_적는다() {
        var held1 = pkg(1, "CVE-2026-1", "bcprov-jdk18on", "1.81", "UNREACHABLE", "1.80.2", "1.81.1", "1.84");
        var held2 = pkg(2, "CVE-2026-2", "bcprov-jdk18on", "1.81", "UNREACHABLE", "1.85");
        var jackson3 = pkg(3, "CVE-2026-3", "jackson-databind", "3.1.5", "UNREACHABLE", "2.21.7", "3.1.7");

        var chapter = ReachReportChapterProvider.chapter(scope(held1, held2, jackson3), FROM, TO);
        assertThat(chapter.remediations()).isEmpty();
        assertThat(chapter.scope()).anySatisfy(item -> {
            assertThat(item.label()).startsWith("보류 건만 있는 패키지");
            assertThat(item.value()).isEqualTo("Jackson 3.1.5 → 3.1.7 (1건) · bcprov-jdk18on 1.81 → 1.85 (2건)");
        });
    }

    @Test
    void 스캐너_제목_앞의_패키지_좌표를_걷어_낸다() {
        assertThat(ReachReportChapterProvider.shortTitle("com.fasterxml.jackson.core/jackson-databind: "
                + "tools.jackson.core:jackson-databind: Jackson-databind: Denial of Service via quadratic forward-reference completion",
                "jackson-databind")).isEqualTo("Denial of Service via quadratic forward-reference completion");
        assertThat(ReachReportChapterProvider.shortTitle("jackson-databind: com.fasterxml.jackson/jackson-core: "
                + "jackson-databind: Denial of Service via unbounded cache growth", "jackson-databind"))
                .isEqualTo("Denial of Service via unbounded cache growth");
        assertThat(ReachReportChapterProvider.shortTitle("HTTP/2: header handling", "tomcat-embed-core"))
                .as("패키지 이름이 없는 앞 조각은 그대로").isEqualTo("HTTP/2: header handling");
        assertThat(ReachReportChapterProvider.bootProperty(pkg(1, "C", "jackson-core", "2.21.5", "UNKNOWN")))
                .isEqualTo("jackson-2-bom.version");
        assertThat(ReachReportChapterProvider.bootProperty(pkg(1, "C", "jackson-core", "3.1.5", "UNKNOWN")))
                .isEqualTo("jackson-bom.version");
        assertThat(ReachReportChapterProvider.bootProperty(pkg(1, "C", "bcprov-jdk18on", "1.81", "UNKNOWN"))).isNull();
    }

    @Test
    void L3는_판정을_올렸을_때만_확인이라고_쓴다() {
        // 응답마다 실행되는 Tomcat 구간: 실행됐지만 서버가 판정을 올리지 않았다(도구 판정 확인 못 함 그대로)
        var ran = new ReportRow(11, "API", "reused-api @ 1a2b3c4d", true, SCANNED, "CVE-2026-77756", "HIGH", "tomcat-embed-core",
                "11.0.24", null, null, null, List.of(), "UNKNOWN", "RULE", "규칙", null, "UNREVIEWED", null, "REGION", false, FIRST);
        assertThat(ReachReportChapterProvider.evidence(ran, "UNKNOWN"))
                .contains("L3: 취약 구간 실행됨 (판정은 그대로)").doesNotContain("실행 확인");
        // 규칙이 처음부터 도달 가능이고 구간도 실행됐지만 L3가 올린 것은 아니다(91776처럼 한도가 확인 못 함까지인 CVE 포함)
        var already = new ReportRow(14, "API", "reused-api @ 1a2b3c4d", true, SCANNED, "CVE-2026-91776", "HIGH", "jackson-databind",
                "3.1.5", null, null, null, List.of(), "REACHABLE", "RULE", "규칙", null, "UNREVIEWED", null, "REGION", false, FIRST);
        assertThat(ReachReportChapterProvider.evidence(already, "REACHABLE"))
                .contains("L3: 취약 구간 실행됨 (판정은 그대로)").doesNotContain("실행 확인");
        // L3가 올린 판정
        var raised = new ReportRow(12, "API", "reused-api @ 1a2b3c4d", true, SCANNED, "CVE-2026-89407", "HIGH", "jackson-core",
                "3.1.5", null, null, null, List.of(), "REACHABLE", "RULE", "L3: …", null, "UNREVIEWED", null, "REGION", true, FIRST);
        assertThat(ReachReportChapterProvider.evidence(raised, "REACHABLE")).contains("L3: 실제 실행으로 판정을 올림");
        // L3가 올린 판정의 요약은 서버가 붙인 L3 문장을 떼고 L2 판정의 이유만 쓴다
        var capped76183 = new ReportRow(15, "API", "reused-api @ 1a2b3c4d", true, SCANNED, "CVE-2026-76183", "CRITICAL",
                "tomcat-embed-websocket", "11.0.24", null, null, null, List.of(), "UNKNOWN", "RULE",
                "L3: 이미지를 띄워 보낸 요청에서 취약 구간이 실행됐다. 이 구간은 그 기능을 쓸 때 실행되지만 취약 조건까지 보여 주지는 않아, "
                        + "도달 불가를 확인 못 함으로 올렸다. L2 판정은 도달 불가였다: 앱에 WebSocket 엔드포인트가 없다.",
                null, "UNREVIEWED", null, "REGION", true, FIRST);
        assertThat(ReachReportChapterProvider.evidence(capped76183, "UNKNOWN"))
                .contains("도구: 확인 못 함 (규칙) — 앱에 WebSocket 엔드포인트가 없다.").contains("L3: 실제 실행으로 판정을 올림");
        assertThat(ReachReportChapterProvider.response(raised, "REACHABLE")).isEqualTo("미조치 · 도달 가능 (L3 실행 확인)");
        assertThat(ReachReportChapterProvider.response(ran, "REACHABLE")).isEqualTo("미조치 · 도달 가능");
        // 사람의 잠정 판정으로 도달 가능인데 L3는 확인 못 함까지만 올린 경우: L3가 도달 가능을 확인한 것이 아니다
        var capped = new ReportRow(13, "API", "reused-api @ 1a2b3c4d", true, SCANNED, "CVE-2026-76183", "HIGH", "tomcat-embed-websocket",
                "11.0.24", null, null, null, List.of(), "UNKNOWN", "RULE", "L3: …", null, "PROVISIONAL", "REACHABLE", "REGION", true, FIRST);
        assertThat(ReachReportChapterProvider.response(capped, "REACHABLE")).isEqualTo("미조치 · 도달 가능");
    }

    @Test
    void 사람_메모와_식별자는_넣지_않고_규칙_문장만_쓴다() {
        var manual = new ReportRow(9, "API", "reused-api @ 1a2b3c4d", true, SCANNED, "CVE-2026-9", "HIGH", "bcprov",
                "1.81", null, null, null, List.of(), "REACHABLE", "MANUAL", "메모: 운영 계정 794386801311 확인함", null,
                "CONFIRMED", "REACHABLE", null, false, FIRST);

        var finding = ReachReportChapterProvider.finding(manual, "REACHABLE", "HIGH", "bcprov 수정 버전 없음: 완화책 검토");
        var all = String.join("|", finding.id(), finding.title(), finding.asset(), finding.location(),
                finding.evidence(), finding.action(), finding.response());
        assertThat(all).doesNotContain("운영 계정", "794386801311", "dkr.ecr");
        assertThat(finding.evidence()).contains("사람 판정 (메모는 대시보드)");
        assertThat(finding.id().length()).isLessThanOrEqualTo(40);
        assertThat(finding.assignee()).isEqualTo("미지정");
        assertThat(finding.dueAt()).as("기한은 공통 기능이 기본값으로 채운다").isNull();

        var tool = ReachReportChapterProvider.finding(row(1, "CVE-2026-1", "HIGH", "UNKNOWN", "RULE", "UNREVIEWED", null),
                "UNKNOWN", "HIGH", "x");
        assertThat(tool.evidence()).isEqualTo("도구: 확인 못 함 (규칙) — HTTP/2를 켜는 설정이나 코드가 없다.");
        assertThat(tool.asset()).isEqualTo("API 운영 이미지 (reused-api @ 1a2b3c4d)");
        assertThat(tool.foundAt()).isEqualTo(FIRST);
    }

    @Test
    void 조치는_같은_줄의_수정_버전으로_올리기이고_공통_조치에_묶인다() {
        var critical = row(1, "CVE-2026-1", "CRITICAL", "REACHABLE", "CALLGRAPH", "UNREVIEWED", null);
        var high = row(2, "CVE-2026-2", "HIGH", "UNKNOWN", "RULE", "UNREVIEWED", null);

        assertThat(ReachReportChapterProvider.action(critical)).isEqualTo("Tomcat 11.0.26 이상으로 올리기");
        assertThat(ReachReportChapterProvider.fixVersion("1.81", List.of("1.80.2", "1.81.1", "1.84"))).isEqualTo("1.81.1");
        assertThat(ReachReportChapterProvider.fixVersion("2.0", List.of("1.9"))).isNull();
        var chapter = ReachReportChapterProvider.chapter(scope(critical, high), FROM, TO);
        assertThat(chapter.remediations()).singleElement().satisfies(r -> {
            assertThat(r.title()).isEqualTo("Tomcat 11.0.26 이상으로 올리기");
            assertThat(r.impact()).isEqualTo("Critical 1 · High 1 · 그 밖 0건 (API)");
        });
        // ReportComposer는 action에 조치 제목이 들어 있는 Finding을 그 조치에 묶는다
        assertThat(chapter.findings()).allSatisfy(f -> assertThat(f.action()).contains(chapter.remediations().get(0).title()));
    }

    @Test
    void 실행_중_기준을_못_쓰면_알린다() {
        var latest = new ReachQueryService.ReportScope("LATEST", List.of(), 2, List.of("WEB"));

        var chapter = ReachReportChapterProvider.chapter(latest, FROM, TO);
        assertThat(chapter.note()).contains("L1 조회가 48시간 넘게 없어", "스캔 결과가 없는 이미지가 2개");
        assertThat(chapter.scope()).anySatisfy(item -> assertThat(item.value()).isEqualTo("WEB"));
        assertThat(chapter.findings()).isEmpty();
        assertThat(chapter.dataAsOf()).isNull();
    }
}
