package com.logssey.report;

import java.time.Duration;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 파트 데이터로 리포트 본문을 만든다. DB·스프링 없이 계산만 한다.
 * - 기한이 없는 건에 기본 기한(발견일 + 위험도별 일수)을 채운다
 * - 처리 우선순위 5건을 고른다 (기한 초과 → 위험도 높은 순 → 발견이 오래된 순)
 */
public final class ReportComposer {

    /** 위험도 순서. 미평가는 Low 아래에 따로 둔다 */
    public static final List<String> SEVERITIES = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNASSESSED");

    /** 기본 대응 기한 (CISA BOD 19-02 · FedRAMP 참고). 미평가는 기한을 두지 않는다 */
    static final Map<String, Integer> DEFAULT_DUE_DAYS = Map.of("CRITICAL", 15, "HIGH", 30, "MEDIUM", 90, "LOW", 180);

    static final int PRIORITY_LIMIT = 5;
    static final Duration DUE_SOON = Duration.ofDays(7);
    static final Duration STALE_AFTER = Duration.ofHours(24);

    private ReportComposer() {
    }

    public static ReportContent compose(String name, LocalDate from, LocalDate to, OffsetDateTime now, String createdBy,
                                        ReportChapter chapter, ReportAdvice advice) {
        return compose(name, from, to, now, createdBy, chapter, advice, true);
    }

    /** connected=false: 파트가 아직 장을 제공하지 않아 데이터 없이 만든 리포트 */
    public static ReportContent compose(String name, LocalDate from, LocalDate to, OffsetDateTime now, String createdBy,
                                        ReportChapter chapter, ReportAdvice advice, boolean connected) {
        var findings = withDefaultDue(chapter.findings());
        long overdue = 0, soon = 0, byDefault = 0;
        for (var f : findings) {
            if (f.dueAt() == null) continue;
            if (f.dueAt().isBefore(now)) overdue++;
            else if (f.dueAt().isBefore(now.plus(DUE_SOON))) soon++;
            if (f.dueDefault()) byDefault++;
        }
        Map<String, Long> counts = new LinkedHashMap<>();
        SEVERITIES.forEach(s -> counts.put(s, chapter.severityCounts().getOrDefault(s, 0L)));

        boolean stale = chapter.dataAsOf() == null || chapter.dataAsOf().isBefore(now.minus(STALE_AFTER));
        return new ReportContent(name, chapter.part(), from, to, now, createdBy,
                new ReportContent.Overview(connected, chapter.dataAsOf(), connected && stale, chapter.headline(), chapter.keyMetric(),
                        chapter.newInPeriod(), chapter.resolvedInPeriod(), chapter.note()),
                new ReportContent.Vulnerabilities(chapter.unit(), counts, overdue, soon, byDefault, sorted(findings)),
                new ReportContent.Remediation(actions(chapter.remediations(), findings), advice),
                priorities(findings, now),
                new ReportContent.Appendix(chapter.scope(), chapter.criteria(), chapter.links()));
    }

    /** 조치마다 해결되는 취약점을 묶고, 많이 해결하는 조치부터 번호를 붙인다 (같으면 파트가 준 순서) */
    static List<ReportContent.Action> actions(List<ReportChapter.Remediation> remediations, List<ReportFinding> findings) {
        record Covered(ReportChapter.Remediation remediation, List<String> ids, int order) {
        }
        List<Covered> covered = new ArrayList<>();
        for (int i = 0; i < remediations.size(); i++) {
            var r = remediations.get(i);
            var ids = sorted(findings).stream().filter(f -> f.action() != null && f.action().contains(r.title()))
                    .map(ReportFinding::id).toList();
            covered.add(new Covered(r, ids, i));
        }
        covered.sort(Comparator.comparing((Covered c) -> -c.ids().size()).thenComparing(Covered::order));
        List<ReportContent.Action> result = new ArrayList<>();
        for (int i = 0; i < covered.size(); i++) {
            var c = covered.get(i);
            result.add(new ReportContent.Action(i + 1, c.remediation().title(), c.remediation().how(),
                    c.remediation().impact(), c.remediation().link(), c.ids()));
        }
        return result;
    }

    static List<ReportFinding> withDefaultDue(List<ReportFinding> findings) {
        return findings.stream().map(f -> {
            Integer days = DEFAULT_DUE_DAYS.get(f.severity());
            if (f.dueAt() != null || days == null || f.foundAt() == null) {
                return f;
            }
            return f.withDue(f.foundAt().plusDays(days), true);
        }).toList();
    }

    static int rank(String severity) {
        int i = SEVERITIES.indexOf(severity);
        return i < 0 ? SEVERITIES.size() : i;
    }

    /** 위험도 높은 순 → 발견이 오래된 순 (1번 절의 목록 순서) */
    static List<ReportFinding> sorted(List<ReportFinding> findings) {
        return findings.stream().sorted(Comparator.comparing((ReportFinding f) -> rank(f.severity()))
                .thenComparing(ReportFinding::foundAt, Comparator.nullsLast(Comparator.naturalOrder()))).toList();
    }

    /** 기한 초과 → 위험도 높은 순 → 발견이 오래된 순으로 5건. 미평가는 뺀다 */
    static List<ReportContent.Priority> priorities(List<ReportFinding> findings, OffsetDateTime now) {
        List<ReportFinding> picked = findings.stream()
                .filter(f -> !"UNASSESSED".equals(f.severity()))
                .sorted(Comparator.comparing((ReportFinding f) -> !(f.dueAt() != null && f.dueAt().isBefore(now)))
                        .thenComparing(f -> rank(f.severity()))
                        .thenComparing(ReportFinding::foundAt, Comparator.nullsLast(Comparator.naturalOrder())))
                .limit(PRIORITY_LIMIT).toList();
        List<ReportContent.Priority> result = new ArrayList<>();
        for (int i = 0; i < picked.size(); i++) {
            var f = picked.get(i);
            result.add(new ReportContent.Priority(i + 1, f, f.dueAt() != null && f.dueAt().isBefore(now)));
        }
        return result;
    }
}
