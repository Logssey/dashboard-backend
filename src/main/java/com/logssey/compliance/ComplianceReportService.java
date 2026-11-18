package com.logssey.compliance;

import static com.logssey.compliance.ComplianceDtos.ResultItem;
import static com.logssey.compliance.ComplianceDtos.RunSummary;
import static com.logssey.compliance.ComplianceDtos.AssessmentContext;

import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** 저장된 Run Snapshot으로 인쇄 가능한 독립 HTML 감사 보고서를 만든다. */
@Service
public class ComplianceReportService {

    private static final int MAX_FINDINGS = 1_000;
    private static final DateTimeFormatter REPORT_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm z")
            .withZone(ZoneId.of("Asia/Seoul"));
    private static final Map<String, String> STATUS_LABELS = Map.of(
            "TECHNICAL_FAIL", "기술 실패",
            "TECHNICALLY_SATISFIED", "기술 충족",
            "NEEDS_REVIEW", "검토 필요",
            "NOT_ASSESSED", "미점검");

    private final ComplianceRepository repository;
    private final ComplianceCatalog catalog;
    private final ComplianceCheckPolicyCatalog checkPolicies;
    private final ComplianceTargetRepository targets;
    private final String targetKey;
    private final String targetName;

    public ComplianceReportService(ComplianceRepository repository, ComplianceCatalog catalog,
                                   ComplianceCheckPolicyCatalog checkPolicies, ComplianceTargetRepository targets,
                                   @Value("${logssey.compliance.target-key:default}") String targetKey,
                                   @Value("${logssey.compliance.target-name:점검 대상}") String targetName) {
        this.repository = repository;
        this.catalog = catalog;
        this.checkPolicies = checkPolicies;
        this.targets = targets;
        this.targetKey = targetKey;
        this.targetName = targetName;
    }

    @Transactional(readOnly = true)
    public ReportDocument report(String requestedTarget, long runId, String requestedFramework) {
        String scope = normalizeFramework(requestedFramework);
        String selectedTarget = target(requestedTarget);
        RunSummary run = repository.run(selectedTarget, runId)
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        AssessmentContext assessmentContext = repository.assessmentContext(runId);
        String selectedTargetName = targets.find(selectedTarget)
                .map(ComplianceTargetDtos.TargetSummary::displayName).orElse(targetName);
        List<ComplianceCatalog.Framework> frameworks = scope.equals("all")
                ? catalog.frameworks()
                : List.of(requiredFramework(scope));
        List<String> frameworkIds = frameworks.stream().map(ComplianceCatalog.Framework::id).toList();
        var assessmentRows = repository.assessments(runId, frameworkIds);
        var assessments = new HashMap<String, ComplianceRepository.AssessmentRow>();
        for (var row : assessmentRows) assessments.put(row.frameworkId() + ":" + row.controlId(), row);

        Set<String> mappedChecks = new HashSet<>();
        for (var framework : frameworks) {
            for (var control : framework.controls()) {
                control.mappings().forEach(mapping -> mappedChecks.add(mapping.key()));
            }
        }
        // 개별 규제 보고서는 전체 비통과 결과에서 매핑을 고른 뒤 1,000건으로 제한한다.
        // 먼저 전역 제한을 걸면 앞쪽의 다른 규제 Finding 때문에 해당 규제 결과가 누락될 수 있다.
        var reportResults = repository.reportResults(runId, ProwlerOcsfNormalizer.MAX_RESULTS + 1);
        var selectedResults = reportResults.stream()
                .filter(result -> scope.equals("all")
                        || mappedChecks.contains(result.provider().toLowerCase(Locale.ROOT) + ":" + result.checkId()))
                .toList();
        boolean truncated = selectedResults.size() > MAX_FINDINGS;
        if (truncated) selectedResults = selectedResults.subList(0, MAX_FINDINGS);

        String filename = "logssey-compliance-run-" + runId + "-" + (scope.equals("all") ? "integrated" : scope) + ".html";
        return new ReportDocument(filename,
                render(run, assessmentContext, frameworks, assessments, selectedResults, truncated,
                        scope, selectedTargetName)
                        .getBytes(StandardCharsets.UTF_8));
    }

    private String render(RunSummary run, AssessmentContext assessmentContext,
                          List<ComplianceCatalog.Framework> frameworks,
                          Map<String, ComplianceRepository.AssessmentRow> assessments,
                          List<ResultItem> findings, boolean findingsTruncated, String scope,
                          String selectedTargetName) {
        String reportLabel = scope.equals("all") ? "통합" : frameworks.getFirst().shortName();
        String reportId = "CMP-" + run.runId() + "-" + scope.toUpperCase(Locale.ROOT);
        var html = new StringBuilder(64_000);
        html.append("<!doctype html><html lang=\"ko\"><head><meta charset=\"utf-8\">")
                .append("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
                .append("<title>").append(h(reportLabel)).append(" 컴플라이언스 감사 결과 보고서</title>")
                .append("<style>").append(styles()).append("</style></head><body>")
                .append("<aside class=\"print-help\">브라우저 인쇄 메뉴에서 PDF로 저장할 수 있습니다.</aside>")
                .append("<main class=\"report\"><section class=\"cover page\">")
                .append("<header class=\"brand\"><b>logssey</b><span>CLOUD SECURITY</span></header>")
                .append("<div class=\"cover-main\"><p class=\"eyebrow\">AUDIT RESULT REPORT</p><h1>")
                .append(h(reportLabel)).append(" 컴플라이언스<br>감사 결과 보고서</h1>")
                .append("<p>클라우드 구성 점검 결과를 규제 통제별 기술 근거로 정리한 Run Snapshot 보고서입니다.</p></div>")
                .append("<dl class=\"cover-meta\">")
                .append(meta("대상 서비스", selectedTargetName))
                .append(meta("대상 환경", environmentLabel(run.environment())))
                .append(meta("점검 엔진", run.product() + " " + run.scannerVersion()))
                .append(meta("판정 정책", policyVersionLabel(assessmentContext.policyVersion())))
                .append(meta("점검 완료", REPORT_TIME.format(run.finishedAt())))
                .append(meta("보고서 생성", REPORT_TIME.format(OffsetDateTime.now())))
                .append(meta("보고서 ID", reportId))
                .append("</dl><p class=\"classification\">INTERNAL · 기술 점검 근거 자료</p></section>");

        int totalControls = frameworks.stream().mapToInt(framework -> framework.controls().size()).sum();
        Map<String, Integer> totals = statusCounts(assessmentRows(assessments));
        html.append("<section class=\"page\"><div class=\"section-heading\"><span>01</span><div><h2>점검 요약</h2><p>선택한 Run과 보고서 범위</p></div></div>")
                .append("<div class=\"summary-grid\">")
                .append(metric("규제 기준", frameworks.size(), "개", ""))
                .append(metric("전체 통제", totalControls, "개", ""))
                .append(metric("기술 실패", totals.getOrDefault("TECHNICAL_FAIL", 0), "개", "danger"))
                .append(metric("검토 필요", totals.getOrDefault("NEEDS_REVIEW", 0), "개", "warning"))
                .append("</div><div class=\"run-panel\"><dl>")
                .append(meta("Run", "#" + run.runId()))
                .append(meta("점검 원본", run.source()))
                .append(meta("정규화 결과", run.counts().total() + "건"))
                .append(meta("실패 기술 결과", run.counts().fail() + "건"))
                .append(meta("수집 오류", run.counts().error() + "건"))
                .append(meta("자동 식별 서비스", inferredServices(assessmentContext.inferredServices())))
                .append(meta("적용성 프로필", profileSummary(assessmentContext)))
                .append(meta("가져온 사용자", run.createdBy()))
                .append("</dl></div><div class=\"disclaimer\"><b>판정 범위</b><p>이 보고서는 자동 수집 가능한 기술 설정 근거를 정리합니다. 조직 운영, 문서, 인터뷰와 수동 증거를 포함한 인증 적합 여부를 확정하지 않습니다.</p></div></section>");

        int sectionNumber = 2;
        for (var framework : frameworks) {
            html.append("<section class=\"page framework-page\"><div class=\"section-heading\"><span>")
                    .append(String.format("%02d", sectionNumber++)).append("</span><div><h2>")
                    .append(h(framework.name())).append("</h2><p>").append(framework.controls().size())
                    .append("개 통제의 기술 근거 상태</p></div></div>");
            Map<String, Integer> frameworkCounts = statusCounts(assessmentRows(assessments).stream()
                    .filter(row -> row.frameworkId().equals(framework.id())).toList());
            html.append("<div class=\"status-strip\">");
            for (String status : List.of("TECHNICAL_FAIL", "TECHNICALLY_SATISFIED", "NEEDS_REVIEW", "NOT_ASSESSED")) {
                html.append("<div class=\"").append(statusClass(status)).append("\"><span>")
                        .append(STATUS_LABELS.get(status)).append("</span><strong>")
                        .append(frameworkCounts.getOrDefault(status, 0)).append("</strong></div>");
            }
            html.append("</div><table><thead><tr><th>통제</th><th>상태</th><th>매핑</th><th>관측</th><th>실패</th></tr></thead><tbody>");
            for (var control : framework.controls()) {
                var row = assessments.get(framework.id() + ":" + control.id());
                String status = row == null ? "NOT_ASSESSED" : row.status();
                html.append("<tr><td><b>").append(h(control.id())).append(" · ").append(h(control.title()))
                        .append("</b><small>").append(h(shorten(control.description(), 190))).append("</small></td><td><span class=\"pill ")
                        .append(statusClass(status)).append("\">").append(STATUS_LABELS.get(status)).append("</span></td><td>")
                        .append(row == null ? control.mappings().size() : row.mappedCheckCount()).append("</td><td>")
                        .append(row == null ? 0 : row.observedCheckCount()).append("</td><td>")
                        .append(row == null ? 0 : row.failedCheckCount()).append("</td></tr>");
            }
            html.append("</tbody></table></section>");
        }

        html.append("<section class=\"page\"><div class=\"section-heading\"><span>")
                .append(String.format("%02d", sectionNumber)).append("</span><div><h2>기술 Finding 부록</h2><p>선택한 기준에 연결된 실패·오류·검토 필요 결과</p></div></div>");
        if (findings.isEmpty()) {
            html.append("<div class=\"empty\">보고서 범위에 포함되는 비통과 기술 결과가 없습니다.</div>");
        } else {
            html.append("<table><thead><tr><th>Check</th><th>결과</th><th>자산</th><th>현재 값</th><th>개선 가이드</th></tr></thead><tbody>");
            for (var finding : findings) {
                var guide = checkPolicies.guide(finding.provider(), finding.checkId(), finding.expectedValue());
                html.append("<tr><td><b>").append(h(finding.title())).append("</b><small>")
                        .append(h(finding.checkId())).append("</small></td><td><span class=\"pill ")
                        .append(resultClass(finding.result())).append("\">").append(resultLabel(finding.result()))
                        .append("</span></td><td>").append(h(finding.asset())).append("<small>")
                        .append(h(finding.region())).append("</small></td><td>").append(h(shorten(finding.currentValue(), 180)))
                        .append("</td><td><b>").append(h(guide.expectedState())).append("</b><small>적용 조건 · ")
                        .append(h(guide.applicability())).append("</small><small>검증 · ")
                        .append(h(guide.verification())).append("</small><small>롤백 · ")
                        .append(h(guide.rollback())).append("</small>")
                        .append("</td></tr>");
            }
            html.append("</tbody></table>");
            if (findingsTruncated) html.append("<p class=\"limit-note\">우선순위가 높은 1,000건만 포함했습니다.</p>");
        }
        html.append("<div class=\"limitations\"><h3>해석 시 유의사항</h3><ol><li>기술 충족은 실행된 매핑 Check가 모두 관측되고 실패하지 않았다는 의미이며 인증 적합 판정이 아닙니다.</li><li>미점검은 통제가 불필요하다는 의미가 아니라 현재 Run에서 기술 근거가 수집되지 않았다는 의미입니다.</li><li>CSAP의 부분·보조 매핑은 단독으로 통제 충족을 증명하지 않습니다.</li><li>수동 증거, 적용성 판단과 예외 승인은 별도의 검토가 필요합니다.</li></ol></div></section>")
                .append("</main><footer><span>Logssey · Cloud security, clearly.</span><span>")
                .append(h(reportId)).append("</span></footer></body></html>");
        return html.toString();
    }

    private static List<ComplianceRepository.AssessmentRow> assessmentRows(
            Map<String, ComplianceRepository.AssessmentRow> assessments) {
        return new ArrayList<>(assessments.values());
    }

    private static Map<String, Integer> statusCounts(List<ComplianceRepository.AssessmentRow> rows) {
        var counts = new HashMap<String, Integer>();
        rows.forEach(row -> counts.merge(row.status(), 1, Integer::sum));
        return counts;
    }

    private ComplianceCatalog.Framework requiredFramework(String id) {
        var framework = catalog.framework(id);
        if (framework == null) throw new ApiException(ErrorCode.INVALID_INPUT, "지원하지 않는 보고서 기준입니다.");
        return framework;
    }

    private static String normalizeFramework(String value) {
        String normalized = value == null ? "all" : value.trim().toLowerCase(Locale.ROOT);
        if (!Set.of("all", "isms", "iso", "csap").contains(normalized)) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "지원하지 않는 보고서 기준입니다.");
        }
        return normalized;
    }

    private String target(String requestedTarget) {
        String selected = requestedTarget == null || requestedTarget.isBlank() ? targetKey : requestedTarget.trim();
        if (!selected.matches("^[a-z0-9][a-z0-9-]{1,98}[a-z0-9]$")) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "점검 대상 키가 올바르지 않습니다.");
        }
        return selected;
    }

    private static String meta(String label, String value) {
        return "<div><dt>" + h(label) + "</dt><dd>" + h(value) + "</dd></div>";
    }

    private static String metric(String label, long value, String unit, String tone) {
        return "<div class=\"" + tone + "\"><span>" + h(label) + "</span><strong>" + value
                + "</strong><small>" + h(unit) + "</small></div>";
    }

    private static String environmentLabel(String environment) {
        return "prod".equals(environment) ? "운영" : "개발";
    }

    private static String inferredServices(List<String> services) {
        return services.isEmpty() ? "식별 없음" : String.join(", ", services).toUpperCase(Locale.ROOT);
    }

    private static String policyVersionLabel(String version) {
        return "legacy".equals(version) ? "레거시 판정 · 프로필 미적용" : "정책 " + version;
    }

    private static String profileSummary(AssessmentContext context) {
        long used = context.profile().serviceUsage().values().stream().filter("USED"::equals).count();
        long notUsed = context.profile().serviceUsage().values().stream().filter("NOT_USED"::equals).count();
        long required = context.profile().requirements().values().stream().filter("REQUIRED"::equals).count();
        long notRequired = context.profile().requirements().values().stream().filter("NOT_REQUIRED"::equals).count();
        return "서비스 사용 " + used + " · 미사용 " + notUsed
                + " · 정책 요구 " + required + " · 비요구 " + notRequired;
    }

    private static String statusClass(String status) {
        return switch (status) {
            case "TECHNICAL_FAIL" -> "fail";
            case "TECHNICALLY_SATISFIED" -> "pass";
            case "NEEDS_REVIEW" -> "review";
            default -> "muted";
        };
    }

    private static String resultClass(String result) {
        return switch (result) {
            case "FAIL" -> "fail";
            case "ERROR" -> "error";
            default -> "review";
        };
    }

    private static String resultLabel(String result) {
        return switch (result) {
            case "FAIL" -> "실패";
            case "ERROR" -> "수집 오류";
            default -> "검토 필요";
        };
    }

    private static String shorten(String value, int max) {
        if (value == null) return "";
        return value.length() <= max ? value : value.substring(0, max - 1) + "…";
    }

    private static String h(Object value) {
        return String.valueOf(value == null ? "" : value)
                .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    private static String styles() {
        return """
                :root{--ink:#1b1f28;--muted:#68707d;--line:#dfe3e9;--soft:#f5f6f8;--accent:#6d5ddd;--fail:#b8374b;--review:#96651a;--pass:#21745c}*{box-sizing:border-box}html{font-family:Pretendard,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--ink);background:#edf0f3}body{margin:0}.print-help{position:sticky;top:0;z-index:2;padding:10px;text-align:center;background:#1b1f28;color:white;font-size:11px}.report{width:210mm;margin:20px auto;background:white;box-shadow:0 18px 60px #16202c1a}.page{padding:17mm 16mm;break-before:page}.cover{min-height:297mm;display:flex;flex-direction:column;break-before:auto}.brand{display:flex;align-items:baseline;gap:9px}.brand b{font-size:24px;letter-spacing:-1px}.brand span{color:var(--muted);font-size:8px;letter-spacing:.18em}.cover-main{margin:auto 0}.eyebrow{color:var(--accent);font-size:10px;font-weight:800;letter-spacing:.2em}.cover h1{margin:14px 0 22px;font-size:38px;line-height:1.22;letter-spacing:-.045em}.cover-main>p:last-child{max-width:130mm;color:var(--muted);font-size:13px;line-height:1.8}.cover-meta{display:grid;grid-template-columns:1fr 1fr;margin:0;border-top:2px solid var(--ink)}.cover-meta div{padding:13px 0;border-bottom:1px solid var(--line)}.cover-meta div:nth-child(odd){padding-right:12px}.cover-meta dt,.run-panel dt{color:var(--muted);font-size:9px}.cover-meta dd,.run-panel dd{margin:5px 0 0;font-size:11px;font-weight:700}.classification{margin:16px 0 0;color:var(--muted);font-size:8px;letter-spacing:.1em}.section-heading{display:flex;gap:13px;align-items:flex-start;margin-bottom:20px}.section-heading>span{margin-top:3px;color:var(--accent);font-size:10px;font-weight:800}.section-heading h2{margin:0;font-size:23px;letter-spacing:-.035em}.section-heading p{margin:4px 0 0;color:var(--muted);font-size:10px}.summary-grid{display:grid;grid-template-columns:repeat(4,1fr);border:1px solid var(--line);border-radius:11px;overflow:hidden}.summary-grid>div{padding:15px;border-right:1px solid var(--line)}.summary-grid>div:last-child{border-right:0}.summary-grid span{display:block;color:var(--muted);font-size:9px}.summary-grid strong{display:inline-block;margin-top:7px;font-size:25px}.summary-grid small{margin-left:3px;color:var(--muted);font-size:9px}.summary-grid .danger strong{color:var(--fail)}.summary-grid .warning strong{color:var(--review)}.run-panel{margin-top:16px;padding:16px;border-radius:11px;background:var(--soft)}.run-panel dl{display:grid;grid-template-columns:repeat(3,1fr);gap:15px;margin:0}.run-panel dl div,.run-panel dl dt,.run-panel dl dd{margin-block:0}.disclaimer{margin-top:15px;padding:14px 16px;border-left:3px solid var(--accent);background:#f8f7ff}.disclaimer b{font-size:10px}.disclaimer p{margin:5px 0 0;color:var(--muted);font-size:9px;line-height:1.65}.status-strip{display:grid;grid-template-columns:repeat(4,1fr);margin-bottom:16px;border:1px solid var(--line);border-radius:9px;overflow:hidden}.status-strip div{padding:11px 13px;border-right:1px solid var(--line)}.status-strip div:last-child{border-right:0}.status-strip span{display:block;color:var(--muted);font-size:8px}.status-strip strong{display:block;margin-top:4px;font-size:18px}.status-strip .fail strong{color:var(--fail)}.status-strip .review strong{color:var(--review)}.status-strip .pass strong{color:var(--pass)}table{width:100%;border-collapse:collapse;font-size:8px;line-height:1.45}thead{display:table-header-group}th{padding:7px;text-align:left;white-space:nowrap;color:var(--muted);background:var(--soft);border-top:1px solid var(--line);border-bottom:1px solid var(--line);font-weight:600}td{padding:8px 7px;vertical-align:top;border-bottom:1px solid var(--line);overflow-wrap:anywhere}td b,td small{display:block}td small{margin-top:3px;color:var(--muted)}tr{break-inside:avoid}.pill{display:inline-block;padding:3px 6px;border-radius:5px;font-size:7px;font-weight:700;white-space:nowrap}.pill.fail{color:var(--fail);background:#fae9ec}.pill.pass{color:var(--pass);background:#e5f4ee}.pill.review{color:var(--review);background:#fff2db}.pill.error{color:#994e18;background:#fff0e2}.pill.muted{color:#66707e;background:#edf0f3}.empty{padding:24px;text-align:center;color:var(--muted);background:var(--soft);font-size:10px}.limit-note{color:var(--muted);font-size:8px}.limitations{margin-top:24px;padding:16px;border-radius:10px;background:var(--soft)}.limitations h3{margin:0 0 8px;font-size:11px}.limitations ol{margin:0;padding-left:18px}.limitations li{padding:4px 0;color:var(--muted);font-size:8px;line-height:1.55}footer{display:none}@media print{html,body{background:white}.print-help{display:none}.report{width:auto;margin:0;box-shadow:none}.page{padding:13mm 12mm}.cover{min-height:270mm}footer{position:fixed;display:flex;justify-content:space-between;bottom:4mm;left:12mm;right:12mm;color:#969da7;font-size:6px}}@page{size:A4;margin:0}
                """;
    }

    public record ReportDocument(String filename, byte[] content) {}
}
