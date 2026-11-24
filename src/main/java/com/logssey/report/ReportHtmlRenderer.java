package com.logssey.report;

import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;

/**
 * 인쇄용 단독 HTML. 컴플라이언스 감사 보고서와 같은 모양(표지 → 번호 붙은 절, A4)으로 그린다.
 * 절: 01 처리 우선순위 → 02 발견된 취약점 → 03 공통 조치 방안 → 04 부록. 저장된 스냅샷만 읽는다.
 */
public final class ReportHtmlRenderer {

    static final int FINDINGS_LIMIT = 300;
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'KST'");
    private static final DateTimeFormatter DAY = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    private static final Map<String, String> SEVERITY = Map.of("CRITICAL", "Critical", "HIGH", "High",
            "MEDIUM", "Medium", "LOW", "Low", "UNASSESSED", "미평가");

    public record Document(String filename, byte[] content) {
    }

    private ReportHtmlRenderer() {
    }

    public static Document render(long reportId, ReportContent c) {
        return render(reportId, c, Map.of());
    }

    /** findingAdvice: 취약점별 AI 대응 방법 (있으면 발견된 취약점 절 아래에 싣는다) */
    public static Document render(long reportId, ReportContent c, Map<String, ReportAdvice> findingAdvice) {
        String id = "RPT-" + reportId;
        var html = new StringBuilder(64_000);
        html.append("<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">")
                .append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
                .append("<title>").append(h(c.name())).append("</title><style>").append(STYLES).append("</style></head><body>")
                .append("<aside class=\"print-help\">브라우저 인쇄 메뉴에서 PDF로 저장할 수 있습니다.</aside><main class=\"report\">");
        cover(html, id, c);
        priorities(html, c);
        vulnerabilities(html, c, findingAdvice);
        remediation(html, c);
        appendix(html, c);
        html.append("</main><footer><span>Logssey · ").append(h(c.part().label())).append(" 리포트</span><span>").append(id)
                .append("</span></footer></body></html>");
        return new Document("logssey-report-" + id + ".html", html.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static void cover(StringBuilder html, String id, ReportContent c) {
        var o = c.overview();
        html.append("<section class=\"cover page\"><header class=\"brand\"><b>logssey</b><span>CLOUD SECURITY</span></header>")
                .append("<div class=\"cover-main\"><p class=\"eyebrow\">").append(h(c.part().label())).append(" REPORT</p><h1>")
                .append(h(c.name())).append("</h1><p>").append(h(o.headline())).append("</p></div><dl class=\"cover-meta\">")
                .append(meta("파트", c.part().label()))
                .append(meta("보고 기간", c.periodFrom() + " ~ " + c.periodTo()))
                .append(meta("생성 시각", time(c.createdAt())))
                .append(meta("생성자", c.createdBy()))
                .append(meta("데이터 기준 시각", time(o.dataAsOf()) + (o.stale() ? " (24시간 넘게 갱신 안 됨)" : "")))
                .append(meta("리포트 ID", id))
                .append("</dl><p class=\"classification\">INTERNAL · 스냅샷 · 비밀값·계정 ID·내부 식별자는 싣지 않음</p></section>");
    }

    private static void vulnerabilities(StringBuilder html, ReportContent c, Map<String, ReportAdvice> findingAdvice) {
        var v = c.vulnerabilities();
        html.append("<section class=\"page\">").append(heading(2, "발견된 취약점", v.unit()))
                .append("<div class=\"disclaimer\"><b>한 줄 결론</b><p>").append(h(c.overview().headline())).append("</p></div>")
                .append("<div class=\"status-strip\">");
        for (String sev : ReportComposer.SEVERITIES) {
            html.append("<div class=\"").append(sev.toLowerCase()).append("\"><span>").append(SEVERITY.get(sev))
                    .append("</span><strong>").append(c.overview().connected() ? v.severityCounts().getOrDefault(sev, 0L) : "—")
                    .append("</strong></div>");
        }
        html.append("</div>");
        if (c.overview().connected()) html.append("<p class=\"limit-note\">기한 초과 ").append(v.overdue()).append("건 · 7일 안 ")
                .append(v.dueSoon()).append("건 · 기본 기한으로 계산 ").append(v.byDefault())
                .append("건 (Critical 15일 · High 30일 · Medium 90일 · Low 180일)</p>");
        if (v.findings().isEmpty()) {
            html.append("<div class=\"empty\">").append(empty(c, "열린 취약점이 없습니다.")).append("</div>");
        } else {
            html.append("<table><thead><tr><th>위험도</th><th>취약점</th><th>위치</th><th>발견일</th><th>기한</th></tr></thead><tbody>");
            v.findings().stream().limit(FINDINGS_LIMIT).forEach(f -> html.append("<tr><td>").append(pill(f.severity()))
                    .append("</td><td><b>").append(h(f.title())).append("</b><small>").append(h(f.id())).append(" · ")
                    .append(h(f.evidence())).append("</small></td><td>").append(h(f.location())).append("</td><td>")
                    .append(day(f.foundAt())).append("</td><td>").append(due(f)).append("</td></tr>"));
            html.append("</tbody></table>");
            if (v.findings().size() > FINDINGS_LIMIT) {
                html.append("<p class=\"limit-note\">위험도가 높은 ").append(FINDINGS_LIMIT).append("건만 실었습니다.</p>");
            }
        }
        if (!findingAdvice.isEmpty()) {
            html.append("<h3>건별 AI 대응 방법</h3>");
            for (var f : v.findings()) {
                var advice = findingAdvice.get(f.id());
                if (advice == null) continue;
                html.append("<div class=\"card\"><b>").append(h(f.id())).append(" · ").append(h(f.title())).append("</b>");
                advice(html, advice);
                html.append("</div>");
            }
        }
        html.append("</section>");
    }

    private static void remediation(StringBuilder html, ReportContent c) {
        var r = c.remediation();
        html.append("<section class=\"page\">").append(heading(3, "공통 조치 방안", "여러 취약점에 함께 적용되는 조치 · 해결하는 취약점이 많은 순"));
        if (r.actions().isEmpty()) {
            html.append("<div class=\"empty\">").append(empty(c, "공통 조치가 없습니다.")).append("</div>");
        }
        r.actions().forEach(a -> html.append("<div class=\"card\"><b><span class=\"rank\">").append(a.rank())
                .append("</span> ").append(h(a.title())).append("</b><p>").append(h(a.how())).append("</p><small>해결되는 취약점 ")
                .append(a.findingIds().size()).append("건").append(a.findingIds().isEmpty() ? "" : ": " + h(ids(a.findingIds())))
                .append(a.impact() == null ? "" : " · " + h(a.impact())).append("</small></div>"));
        var ai = r.advice();
        html.append("<h3>AI 전체 조치 계획</h3>");
        if (ai.request() != null) {
            html.append("<p class=\"limit-note\">요청 내용: ").append(h(ai.request())).append("</p>");
        }
        if (ReportAdvice.GENERATED.equals(ai.status())) {
            html.append("<div class=\"card\">");
            advice(html, ai);
            html.append("</div>");
            html.append("<p class=\"limit-note\">").append(h(ai.model())).append(" · ").append(time(ai.generatedAt()))
                    .append(" · AI 추천은 참고용입니다. 적용 전에 담당자가 확인하세요.</p>");
        } else {
            html.append("<div class=\"empty\">")
                    .append(ReportAdvice.DISABLED.equals(ai.status()) ? "AI 추천이 꺼져 있어 규칙에 따른 조치만 실었습니다."
                            : "AI 추천을 받지 못했습니다 (" + h(ai.reason()) + "). 규칙에 따른 조치를 참고하세요.")
                    .append("</div>");
        }
        html.append("</section>");
    }

    /** AI 대응 방법: 요약 불릿 → 추천(이유 한 줄, 단계) */
    private static void advice(StringBuilder html, ReportAdvice advice) {
        html.append("<ul class=\"plain\">");
        advice.points().forEach(p -> html.append("<li>").append(h(p)).append("</li>"));
        html.append("</ul>");
        for (int i = 0; i < advice.items().size(); i++) {
            var item = advice.items().get(i);
            html.append("<p><b>").append(i + 1).append("순위 · ").append(h(item.title())).append("</b> · ").append(h(item.why()))
                    .append("</p><ol>");
            item.steps().forEach(step -> html.append("<li>").append(h(step)).append("</li>"));
            html.append("</ol>");
        }
    }

    private static void priorities(StringBuilder html, ReportContent c) {
        html.append("<section class=\"page\">").append(heading(1, "처리 우선순위", "기한 초과 → 위험도 → 오래된 순, 급한 것부터 5건"));
        if (c.priorities().isEmpty()) {
            html.append("<div class=\"empty\">").append(empty(c, "처리할 취약점이 없습니다.")).append("</div></section>");
            return;
        }
        for (var p : c.priorities()) {
            var f = p.finding();
            html.append("<div class=\"finding\"><div class=\"finding-head\"><span class=\"rank\">").append(p.rank())
                    .append("</span>").append(pill(f.severity())).append("<b>").append(h(f.title())).append("</b>")
                    .append(p.overdue() ? "<em>기한 초과</em>" : "").append("<small>").append(h(f.id())).append("</small></div><dl>")
                    .append(meta("대상 자산", f.asset())).append(meta("위치", f.location())).append(meta("근거", f.evidence()))
                    .append(meta("대응", f.response())).append(meta("발견일", day(f.foundAt())))
                    .append(meta("기한", f.dueAt() == null ? "—" : day(f.dueAt()) + (f.dueDefault() ? " (기본값)" : "")))
                    .append(meta("담당", f.assignee())).append(meta("조치", f.action())).append("</dl></div>");
        }
        html.append("</section>");
    }

    private static void appendix(StringBuilder html, ReportContent c) {
        var a = c.appendix();
        var o = c.overview();
        html.append("<section class=\"page\">").append(heading(4, "부록", "점검 범위 · 판단 기준 · 참고 링크"))
                .append("<h3>점검 범위</h3><div class=\"run-panel\"><dl>");
        a.scope().forEach(item -> html.append(meta(item.label(), item.value())));
        html.append(meta("데이터 기준 시각", time(o.dataAsOf())));
        if (o.newInPeriod() != null) html.append(meta("보고 기간 신규", o.newInPeriod() + "건"));
        if (o.resolvedInPeriod() != null) html.append(meta("보고 기간 해결", o.resolvedInPeriod() + "건"));
        html.append("</dl></div><h3>판단 기준</h3><ol class=\"plain\">");
        a.criteria().forEach(line -> html.append("<li>").append(h(line)).append("</li>"));
        html.append("</ol><h3>참고 링크</h3><ul class=\"plain\">");
        a.links().forEach(link -> html.append("<li>").append(h(link.label())).append(" · <span class=\"url\">")
                .append(h(link.url().startsWith("/") ? "대시보드 " + link.url() : link.url())).append("</span></li>"));
        html.append("</ul>");
        if (o.note() != null) html.append("<p class=\"limit-note\">").append(h(o.note())).append("</p>");
        html.append("<div class=\"limitations\"><h3>읽을 때 유의사항</h3><ol>")
                .append("<li>이 리포트는 생성 시각의 스냅샷입니다. 이후 조치는 대시보드에서 확인하세요.</li>")
                .append("<li>미평가는 위험이 낮다는 뜻이 아니라, 근거가 모자라 등급을 정하지 못했다는 뜻입니다.</li>")
                .append("<li>위험도는 위험의 크기이고, 막을지(차단·경고)는 대응 칸에 따로 적었습니다.</li>")
                .append("<li>AI 추천은 리포트에 실린 값만 보고 만든 참고안입니다.</li>")
                .append("<li>비밀값, 계정 ID, 내부 IP, 인스턴스 ID, ARN, 시크릿 이름은 싣지 않았습니다.</li>")
                .append("</ol></div></section>");
    }

    /** 데이터 연결 전 리포트의 빈칸은 '없음'이 아니라 '비어 있음'으로 쓴다 */
    private static String empty(ReportContent c, String whenConnected) {
        return c.overview().connected() ? whenConnected : "데이터 연결 전이라 비어 있습니다.";
    }

    /** 취약점 ID 를 10개까지 쓰고 나머지는 개수로 */
    private static String ids(java.util.List<String> ids) {
        return ids.size() <= 10 ? String.join(", ", ids) : String.join(", ", ids.subList(0, 10)) + " 외 " + (ids.size() - 10) + "건";
    }

    private static String heading(int number, String title, String sub) {
        return "<div class=\"section-heading\"><span>" + String.format("%02d", number) + "</span><div><h2>" + h(title)
                + "</h2><p>" + h(sub) + "</p></div></div>";
    }

    private static String pill(String severity) {
        return "<span class=\"pill " + (severity == null ? "unassessed" : severity.toLowerCase()) + "\">"
                + h(SEVERITY.getOrDefault(severity, "미평가")) + "</span>";
    }

    private static String due(ReportFinding f) {
        if (f.dueAt() == null) return "—";
        return day(f.dueAt()) + (f.dueDefault() ? "<small>기본값</small>" : "");
    }

    private static String meta(String label, String value) {
        return "<div><dt>" + h(label) + "</dt><dd>" + h(value == null || value.isBlank() ? "—" : value) + "</dd></div>";
    }

    private static String time(OffsetDateTime at) {
        return at == null ? "— (기록 없음)" : TIME.format(at.atZoneSameInstant(ReportService.KST));
    }

    private static String day(OffsetDateTime at) {
        return at == null ? "—" : DAY.format(at.atZoneSameInstant(ReportService.KST));
    }

    public static String h(Object value) {
        return String.valueOf(value == null ? "" : value)
                .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    /** 컴플라이언스 감사 보고서와 같은 바탕에 위험도 색·카드만 더했다. 코드 취약점 리포트(CodeReportHtml)도 쓴다 */
    public static final String STYLES = """
            :root{--ink:#1b1f28;--muted:#68707d;--line:#dfe3e9;--soft:#f5f6f8;--accent:#6d5ddd;--crit:#b8374b;--high:#b4561a;--med:#96651a;--low:#4f6b8a}*{box-sizing:border-box}html{font-family:Pretendard,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--ink);background:#edf0f3}body{margin:0}.print-help{position:sticky;top:0;z-index:2;padding:10px;text-align:center;background:#1b1f28;color:white;font-size:11px}.report{width:210mm;margin:20px auto;background:white;box-shadow:0 18px 60px #16202c1a}.page{padding:17mm 16mm;break-before:page}.cover{min-height:297mm;display:flex;flex-direction:column;break-before:auto}.brand{display:flex;align-items:baseline;gap:9px}.brand b{font-size:24px;letter-spacing:-1px}.brand span{color:var(--muted);font-size:8px;letter-spacing:.18em}.cover-main{margin:auto 0}.eyebrow{color:var(--accent);font-size:10px;font-weight:800;letter-spacing:.2em}.cover h1{margin:14px 0 22px;font-size:32px;line-height:1.25;letter-spacing:-.045em}.cover-main>p:last-child{max-width:140mm;color:var(--muted);font-size:13px;line-height:1.8}.cover-meta{display:grid;grid-template-columns:1fr 1fr;margin:0;border-top:2px solid var(--ink)}.cover-meta div{padding:13px 0;border-bottom:1px solid var(--line)}.cover-meta div:nth-child(odd){padding-right:12px}.cover-meta dt,.run-panel dt,.finding dt{color:var(--muted);font-size:9px}.cover-meta dd,.run-panel dd{margin:5px 0 0;font-size:11px;font-weight:700}.classification{margin:16px 0 0;color:var(--muted);font-size:8px;letter-spacing:.1em}.section-heading{display:flex;gap:13px;align-items:flex-start;margin-bottom:20px}.section-heading>span{margin-top:3px;color:var(--accent);font-size:10px;font-weight:800}.section-heading h2{margin:0;font-size:23px;letter-spacing:-.035em}.section-heading p{margin:4px 0 0;color:var(--muted);font-size:10px}h3{margin:20px 0 9px;font-size:12px}.run-panel{padding:14px 16px;border-radius:11px;background:var(--soft)}.run-panel dl{display:grid;grid-template-columns:repeat(2,1fr);gap:13px;margin:0}.run-panel dl div,.run-panel dt,.run-panel dd{margin-block:0}.disclaimer{margin-bottom:14px;padding:14px 16px;border-left:3px solid var(--accent);background:#f8f7ff}.disclaimer b{font-size:10px}.disclaimer p{margin:5px 0 0;font-size:12px;font-weight:700;line-height:1.6}.status-strip{display:grid;grid-template-columns:repeat(5,1fr);border:1px solid var(--line);border-radius:9px;overflow:hidden}.status-strip div{padding:11px 13px;border-right:1px solid var(--line)}.status-strip div:last-child{border-right:0}.status-strip span{display:block;color:var(--muted);font-size:8px}.status-strip strong{display:block;margin-top:4px;font-size:18px}.status-strip .critical strong{color:var(--crit)}.status-strip .high strong{color:var(--high)}.status-strip .medium strong{color:var(--med)}.status-strip .low strong{color:var(--low)}.status-strip .unassessed strong{color:var(--muted)}table{width:100%;margin-top:12px;border-collapse:collapse;font-size:8px;line-height:1.45}thead{display:table-header-group}th{padding:7px;text-align:left;white-space:nowrap;color:var(--muted);background:var(--soft);border-top:1px solid var(--line);border-bottom:1px solid var(--line);font-weight:600}td{padding:8px 7px;vertical-align:top;border-bottom:1px solid var(--line);overflow-wrap:anywhere}td b,td small{display:block}td small{margin-top:3px;color:var(--muted)}tr{break-inside:avoid}.pill{display:inline-block;padding:3px 6px;border-radius:5px;font-size:7px;font-weight:700;white-space:nowrap}.pill.critical{color:var(--crit);background:#fae9ec}.pill.high{color:var(--high);background:#fdeee3}.pill.medium{color:var(--med);background:#fff2db}.pill.low{color:var(--low);background:#e8eef5}.pill.unassessed{color:#66707e;background:#edf0f3}.card{margin-bottom:10px;padding:12px 14px;border:1px solid var(--line);border-radius:10px;break-inside:avoid}.card b{font-size:11px}.card p{margin:5px 0 0;font-size:9px;line-height:1.6}.card small{display:block;margin-top:5px;color:var(--muted);font-size:8px}.card ol{margin:6px 0 0;padding-left:16px;font-size:9px;line-height:1.6}.finding{margin-bottom:10px;padding:12px 14px;border:1px solid var(--line);border-radius:10px;break-inside:avoid}.finding-head{display:flex;align-items:center;gap:8px}.finding-head b{font-size:11px}.finding-head em{font-style:normal;color:var(--crit);font-size:8px;font-weight:700}.finding-head small{margin-left:auto;color:var(--muted);font-size:8px}.rank{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;border-radius:50%;background:var(--accent);color:white;font-size:9px;font-weight:800}.finding dl{display:grid;grid-template-columns:repeat(2,1fr);gap:8px 14px;margin:10px 0 0}.finding dl div,.finding dt,.finding dd{margin-block:0}.finding dd{margin:3px 0 0;font-size:9px;line-height:1.5}.plain{margin:0;padding-left:18px;font-size:9px;line-height:1.7}.url{color:var(--muted)}.empty{padding:20px;text-align:center;color:var(--muted);background:var(--soft);font-size:10px;line-height:1.6}.limit-note{color:var(--muted);font-size:8px;line-height:1.6}.limitations{margin-top:20px;padding:16px;border-radius:10px;background:var(--soft)}.limitations h3{margin:0 0 8px;font-size:11px}.limitations ol{margin:0;padding-left:18px}.limitations li{padding:4px 0;color:var(--muted);font-size:8px;line-height:1.55}footer{display:none}@media print{html,body{background:white}.print-help{display:none}.report{width:auto;margin:0;box-shadow:none}.page{padding:13mm 12mm}.cover{min-height:270mm}footer{position:fixed;display:flex;justify-content:space-between;bottom:4mm;left:12mm;right:12mm;color:#969da7;font-size:6px}}@page{size:A4;margin:0}
            """;
}
