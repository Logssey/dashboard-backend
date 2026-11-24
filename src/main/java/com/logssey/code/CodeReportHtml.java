package com.logssey.code;

import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

import static com.logssey.report.ReportHtmlRenderer.STYLES;
import static com.logssey.report.ReportHtmlRenderer.h;

/**
 * 코드 취약점 인쇄용 단독 HTML (리포트·컴플라이언스 감사 보고서와 같은 모양, A4).
 * 절: 01 레포별 마지막 검사 → 02 발견 목록 → 03 검사 기준·정책. 코드 조각은 싣지 않는다.
 */
final class CodeReportHtml {

    static final int FINDINGS_LIMIT = 300;
    private static final ZoneId KST = ZoneId.of("Asia/Seoul");
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'KST'");
    private static final DateTimeFormatter DAY = DateTimeFormatter.ofPattern("yyyyMMdd");
    private static final List<String> SEVERITIES = List.of("HIGH", "MEDIUM", "LOW");
    private static final Map<String, String> LABEL = Map.of("HIGH", "High", "MEDIUM", "Medium", "LOW", "Low");
    private static final Map<String, String> TOOL = Map.of("semgrep", "Semgrep", "spotbugs", "SpotBugs·FindSecBugs");

    record Document(String filename, byte[] content) {
    }

    private CodeReportHtml() {
    }

    static Document render(CodeScanDtos.Overview overview, String createdBy, OffsetDateTime now) {
        var scans = overview.scans();
        long high = scans.stream().mapToLong(CodeScanDtos.Scan::high).sum();
        long medium = scans.stream().mapToLong(CodeScanDtos.Scan::medium).sum();
        long low = scans.stream().mapToLong(CodeScanDtos.Scan::low).sum();
        String headline = scans.isEmpty() ? "아직 올라온 검사 결과가 없습니다."
                : "High " + high + "건 · Medium " + medium + "건 · Low " + low + "건이 발견되었습니다.";
        OffsetDateTime dataAsOf = scans.stream().map(CodeScanDtos.Scan::scannedAt).max(Comparator.naturalOrder()).orElse(null);

        var html = new StringBuilder(64_000);
        html.append("<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">")
                .append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
                .append("<title>코드 취약점 리포트</title><style>").append(STYLES).append("</style></head><body>")
                .append("<aside class=\"print-help\">브라우저 인쇄 메뉴에서 PDF로 저장할 수 있습니다.</aside><main class=\"report\">");
        html.append("<section class=\"cover page\"><header class=\"brand\"><b>logssey</b><span>CLOUD SECURITY</span></header>")
                .append("<div class=\"cover-main\"><p class=\"eyebrow\">CODE SECURITY REPORT</p><h1>코드 취약점 리포트</h1><p>")
                .append(h(headline)).append("</p></div><dl class=\"cover-meta\">")
                .append(meta("대상 레포", String.join(", ", scans.stream().map(s -> s.repository()).distinct().toList())))
                .append(meta("검사 도구", String.join(", ", scans.stream().map(s -> tool(s.tool())).distinct().toList())))
                .append(meta("생성 시각", time(now)))
                .append(meta("생성자", createdBy))
                .append(meta("데이터 기준 시각", time(dataAsOf)))
                .append("</dl><p class=\"classification\">INTERNAL · 스냅샷 · 코드 조각은 싣지 않음</p></section>");

        html.append("<section class=\"page\">").append(heading(1, "레포별 마지막 검사", "레포 · 도구마다 마지막 검사"))
                .append("<div class=\"status-strip\" style=\"grid-template-columns:repeat(3,1fr)\">")
                .append(cell("high", "High", high)).append(cell("medium", "Medium", medium)).append(cell("low", "Low", low))
                .append("</div>");
        if (scans.isEmpty()) {
            html.append("<div class=\"empty\">서비스 레포의 code-scan 워크플로가 develop에서 돌면 결과가 생깁니다.</div>");
        } else {
            html.append("<table><thead><tr><th>레포</th><th>도구</th><th>커밋</th><th>검사 시각</th><th>High</th><th>Medium</th><th>Low</th></tr></thead><tbody>");
            for (var s : scans) {
                html.append("<tr><td>").append(h(s.repository())).append("</td><td>").append(h(tool(s.tool())))
                        .append("</td><td>").append(h(s.commit().substring(0, 7))).append("</td><td>").append(time(s.scannedAt()))
                        .append("</td><td>").append(s.high()).append("</td><td>").append(s.medium()).append("</td><td>")
                        .append(s.low()).append("</td></tr>");
            }
            html.append("</tbody></table>");
        }
        html.append("</section>");

        var findings = overview.findings();
        html.append("<section class=\"page\">").append(heading(2, "발견 목록", "심각도 순 · 도구가 낸 원문 설명"));
        if (findings.isEmpty()) {
            html.append("<div class=\"empty\">발견이 없습니다.</div>");
        } else {
            html.append("<table><thead><tr><th>심각도</th><th>규칙</th><th>위치</th><th>설명</th><th>도구</th></tr></thead><tbody>");
            findings.stream().limit(FINDINGS_LIMIT).forEach(f -> html.append("<tr><td>")
                    .append("<span class=\"pill ").append(f.severity().toLowerCase()).append("\">").append(LABEL.get(f.severity()))
                    .append("</span></td><td>").append(h(rule(f.ruleId()))).append(f.cwe() == null ? "" : "<br><small>" + h(f.cwe()) + "</small>")
                    .append("</td><td>").append(h(f.path() + (f.line() == null ? "" : ":" + f.line()))).append("<br><small>")
                    .append(h(f.repository())).append("</small></td><td>").append(h(f.message())).append("</td><td>")
                    .append(h(tool(f.tool()))).append("</td></tr>"));
            html.append("</tbody></table>");
            if (findings.size() > FINDINGS_LIMIT) {
                html.append("<p class=\"limit-note\">").append(findings.size()).append("건 중 앞의 ").append(FINDINGS_LIMIT)
                        .append("건만 실었습니다. 전체는 대시보드에서 확인하세요.</p>");
            }
        }
        html.append("</section>");

        html.append("<section class=\"page\">").append(heading(3, "검사 기준 · 정책", "security-solution-docs code-security/policy.md 요약"))
                .append("<table><thead><tr><th>레포</th><th>도구</th><th>규칙 묶음</th></tr></thead><tbody>")
                .append("<tr><td>service-backend</td><td>Semgrep 1.185.0</td><td>p/default · p/java · p/typescript · p/owasp-top-ten</td></tr>")
                .append("<tr><td>service-backend</td><td>SpotBugs 6.5.13 + FindSecBugs 1.14.0</td><td>SECURITY 분류만</td></tr>")
                .append("<tr><td>service-frontend</td><td>Semgrep 1.185.0</td><td>p/default · p/typescript · p/react · p/owasp-top-ten</td></tr>")
                .append("</tbody></table>")
                .append("<table><thead><tr><th>도구 등급 (SARIF level)</th><th>심각도</th><th>뜻</th></tr></thead><tbody>")
                .append("<tr><td>error</td><td>High</td><td>악용 경로가 뚜렷한 패턴</td></tr>")
                .append("<tr><td>warning</td><td>Medium</td><td>입력 검증 여부를 사람이 봐야 하는 패턴</td></tr>")
                .append("<tr><td>note · 그 밖</td><td>Low</td><td>참고</td></tr>")
                .append("</tbody></table>")
                .append("<p class=\"limit-note\">두 도구 모두 Critical 등급을 내지 않아 3단계입니다. 검사는 리포트 전용으로 머지를 막지 않으며,")
                .append(" 오탐을 정리한 뒤 새로 생긴 High만 차단하는 단계로 넘어갑니다. 라이브러리 취약점은 취약점 관리, 시크릿은 시크릿 파트가 맡습니다.</p>")
                .append("</section>");

        html.append("</main><footer><span>Logssey · 코드 취약점 리포트</span><span>").append(time(now))
                .append("</span></footer></body></html>");
        String filename = "logssey-code-report-" + DAY.format(now.atZoneSameInstant(KST)) + ".html";
        return new Document(filename, html.toString().getBytes(StandardCharsets.UTF_8));
    }

    private static String cell(String css, String label, long value) {
        return "<div class=\"" + css + "\"><span>" + label + "</span><strong>" + value + "</strong></div>";
    }

    private static String heading(int number, String title, String sub) {
        return "<div class=\"section-heading\"><span>" + String.format("%02d", number) + "</span><div><h2>" + h(title)
                + "</h2><p>" + h(sub) + "</p></div></div>";
    }

    private static String meta(String label, String value) {
        return "<div><dt>" + h(label) + "</dt><dd>" + h(value == null || value.isBlank() ? "—" : value) + "</dd></div>";
    }

    private static String time(OffsetDateTime at) {
        return at == null ? "—" : TIME.format(at.atZoneSameInstant(KST));
    }

    private static String tool(String tool) {
        return TOOL.getOrDefault(tool, tool);
    }

    private static String rule(String ruleId) {
        int dot = ruleId.lastIndexOf('.');
        return dot < 0 ? ruleId : ruleId.substring(dot + 1);
    }
}
