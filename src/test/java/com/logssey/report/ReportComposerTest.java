package com.logssey.report;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class ReportComposerTest {

    private static final OffsetDateTime NOW = OffsetDateTime.of(2026, 11, 23, 12, 0, 0, 0, ZoneOffset.UTC);
    private static final ReportAdvice OFF = ReportAdvice.notGenerated(ReportAdvice.DISABLED, "DISABLED", null, null);

    private static ReportFinding finding(String id, String severity, int daysAgo) {
        return new ReportFinding(id, "t-" + id, severity, "미조치", null, null, null, NOW.minusDays(daysAgo), null, false,
                null, null, null);
    }

    private static ReportChapter chapter(OffsetDateTime asOf, List<ReportFinding> findings) {
        return new ReportChapter(ReportPart.IAC, asOf, "h", "건", null, List.of(), Map.of("CRITICAL", 1L), findings,
                List.of(), List.of(), List.of(), null, null, null);
    }

    private static ReportContent compose(ReportChapter chapter) {
        return ReportComposer.compose("r", LocalDate.of(2026, 11, 1), LocalDate.of(2026, 11, 23), NOW, "tester", chapter, OFF);
    }

    @Test
    void 기한이_없으면_위험도별_기본값으로_채우고_표시한다() {
        var result = ReportComposer.withDefaultDue(List.of(finding("a", "CRITICAL", 20), finding("b", "UNASSESSED", 3)));

        assertThat(result.get(0).dueAt()).isEqualTo(NOW.minusDays(20).plusDays(15));
        assertThat(result.get(0).dueDefault()).isTrue();
        assertThat(result.get(1).dueAt()).as("미평가는 기한을 두지 않는다").isNull();
    }

    @Test
    void 처리_우선순위는_기한_초과_위험도_오래된_순으로_5건이고_미평가는_뺀다() {
        var content = compose(chapter(NOW, List.of(finding("h1", "HIGH", 1), finding("c-overdue", "CRITICAL", 20),
                finding("c2", "CRITICAL", 2), finding("c1", "CRITICAL", 1), finding("u", "UNASSESSED", 50),
                finding("m-overdue", "MEDIUM", 100), finding("l", "LOW", 1))));

        assertThat(content.priorities()).extracting(p -> p.finding().id())
                .containsExactly("c-overdue", "m-overdue", "c2", "c1", "h1");
        assertThat(content.priorities()).extracting(ReportContent.Priority::rank).containsExactly(1, 2, 3, 4, 5);
        assertThat(content.priorities().get(1).overdue()).isTrue();
    }

    @Test
    void 발견된_취약점은_위험도_순으로_놓이고_분포에_미평가_칸이_있다() {
        var content = compose(chapter(NOW, List.of(finding("l", "LOW", 1), finding("c", "CRITICAL", 1))));

        assertThat(content.vulnerabilities().findings()).extracting(ReportFinding::id).containsExactly("c", "l");
        assertThat(content.vulnerabilities().severityCounts())
                .containsOnlyKeys("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNASSESSED").containsEntry("CRITICAL", 1L);
    }

    @Test
    void 공통_조치는_해결하는_취약점을_묶고_많이_해결하는_것부터_번호를_붙인다() {
        var a = new ReportFinding("a", "a", "HIGH", null, null, null, null, NOW, null, false, null, "끊을 지점: 조치1 또는 조치2", null);
        var b = new ReportFinding("b", "b", "CRITICAL", null, null, null, null, NOW, null, false, null, "끊을 지점: 조치2", null);
        var remediations = List.of(new ReportChapter.Remediation("조치1", "h", null, null),
                new ReportChapter.Remediation("조치2", "h", null, null), new ReportChapter.Remediation("조치3", "h", null, null));

        var actions = ReportComposer.actions(remediations, List.of(a, b));

        assertThat(actions).extracting(ReportContent.Action::title).containsExactly("조치2", "조치1", "조치3");
        assertThat(actions).extracting(ReportContent.Action::rank).containsExactly(1, 2, 3);
        assertThat(actions.getFirst().findingIds()).as("위험도 순").containsExactly("b", "a");
        assertThat(actions.getLast().findingIds()).isEmpty();
    }

    @Test
    void 기한_초과와_7일_안_임박을_센다() {
        var v = compose(chapter(NOW, List.of(finding("a", "CRITICAL", 20), finding("b", "CRITICAL", 10),
                finding("c", "LOW", 1)))).vulnerabilities();

        assertThat(v.overdue()).isEqualTo(1);
        assertThat(v.dueSoon()).isEqualTo(1);
        assertThat(v.byDefault()).isEqualTo(3);
    }

    @Test
    void 데이터가_24시간보다_오래되면_기준_시각_오래됨으로_표시한다() {
        assertThat(compose(chapter(NOW.minusHours(30), List.of())).overview().stale()).isTrue();
        assertThat(compose(chapter(NOW.minusHours(2), List.of())).overview().stale()).isFalse();
    }
}
