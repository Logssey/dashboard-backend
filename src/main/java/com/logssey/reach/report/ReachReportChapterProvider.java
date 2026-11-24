package com.logssey.reach.report;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

import com.logssey.reach.query.ReachQueryRepository.ReportRow;
import com.logssey.reach.query.ReachQueryService;
import com.logssey.reach.rule.ReachVulnFunctionData;
import com.logssey.report.ReportChapter;
import com.logssey.report.ReportChapterProvider;
import com.logssey.report.ReportFinding;
import com.logssey.report.ReportPart;

import org.springframework.stereotype.Component;

/**
 * 공통 리포트의 "취약점(이미지·공급망)" 장. 운영에서 실행 중인 이미지(L1)의 Finding을 넘긴다.
 * <ul>
 *   <li>위험도는 스캐너 심각도 그대로다(UNKNOWN은 UNASSESSED). 도달 판정은 리포트에 넣을지만 정한다: 도달 가능·확인 못 함·판정 전은
 *       findings, 도달 불가는 findings에서 빼고 범위 표에 "보류"로 센다(PRD 원칙 "도달 불가 = 보류", 지우지 않음)</li>
 *   <li>판정은 사람이 확정(CONFIRMED)했으면 사람 판정, 잠정(PROVISIONAL)이면 도구·잠정 중 위험한 쪽(NFR-01), 아니면 도구 판정</li>
 *   <li>같은 앱·패키지·CVE는 한 건(배포 중 실행 중 digest가 둘이면 둘 다 범위에 든다). 발견일은 그 조합이 이미지에 처음 나온 때라
 *       이미지가 바뀌어도 대응 기한이 다시 시작하지 않는다. 기한은 공통 기본값</li>
 *   <li>Finding 칸은 외부 AI(조치 방안)로도 나가므로 검토 메모·사람 판정 요약·설정 원문 근거·레지스트리 주소·워크로드 이름은 넣지 않는다.
 *       판정 요약은 규칙 작성자가 쓴 문장(why_ko)만 쓴다</li>
 * </ul>
 */
@Component
public class ReachReportChapterProvider implements ReportChapterProvider {

    static final String FINDINGS_LINK = "/vulnerabilities/findings";
    static final String BASE_IMAGE = "베이스 이미지 갱신";

    private static final Map<String, String> STATUS = Map.of("REACHABLE", "도달 가능", "UNKNOWN", "확인 못 함",
            "UNREACHABLE", "도달 불가", "NOT_ANALYZED", "판정 전");
    /** 판정 전 사유. 근거 칸에 "판정 전: …"으로 쓴다(대응 칸은 "미조치 · 판정 전"만) */
    private static final Map<String, String> REASON = Map.of("NO_VULN_FUNCTION_DATA", "이 CVE의 판정 데이터가 아직 없음",
            "OS_PACKAGE", "OS 패키지는 판정하지 않음",
            "UNANALYZED_COPY", "같은 CVE의 판정 데이터가 다른 패키지에만 있어 이 패키지는 아직 판정하지 않음",
            "UNSUPPORTED_ECOSYSTEM", "지원하지 않는 언어의 패키지라 판정하지 않음");
    private static final Map<String, String> METHOD = Map.of("CALLGRAPH", "호출 그래프", "RULE", "규칙");
    private static final List<String> SEVERITIES = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNASSESSED");

    private final ReachQueryService query;
    private final ReachVulnFunctionData functions;

    public ReachReportChapterProvider(ReachQueryService query, ReachVulnFunctionData functions) {
        this.query = query;
        this.functions = functions;
    }

    @Override
    public ReportPart part() {
        return ReportPart.VULNERABILITY;
    }

    @Override
    public ReportChapter chapter(OffsetDateTime from, OffsetDateTime to, String loginId) {
        return chapter(query.reportScope(loginId), from, to, functions::summaryKo);
    }

    static ReportChapter chapter(ReachQueryService.ReportScope scope, OffsetDateTime from, OffsetDateTime to) {
        return chapter(scope, from, to, cve -> null);
    }

    /** summaries: CVE의 한국어 요약(판정 데이터 summary_ko). 판정 전 사본의 제목에 쓴다 */
    static ReportChapter chapter(ReachQueryService.ReportScope scope, OffsetDateTime from, OffsetDateTime to,
                                 Function<String, String> summaries) {
        // 같은 앱·패키지·버전·CVE는 한 건(배포 중 실행 중 digest가 둘이어도). 이름이 같아도 버전이 다르면
        // (Jackson 2.x와 3.x) 다른 jar라 따로 센다. 행은 실행 중 이미지가 먼저 온다
        Map<String, ReportRow> unique = new LinkedHashMap<>();
        for (var row : scope.rows()) {
            unique.putIfAbsent(packageKey(row) + "|" + row.vulnerabilityId(), row);
        }
        Map<String, String> upgradeTo = upgradeTo(unique.values());

        List<ReportFinding> findings = new ArrayList<>();
        Map<String, Long> severityCounts = new LinkedHashMap<>();
        SEVERITIES.forEach(s -> severityCounts.put(s, 0L));
        long reachableHigh = 0, unknown = 0, notAnalyzed = 0, judged = 0;
        long heldConfirmed = 0, heldUnreviewed = 0;
        Map<String, Long> heldBySeverity = new LinkedHashMap<>();
        Map<String, List<ReportRow>> byAction = new LinkedHashMap<>();
        Map<String, List<ReportRow>> heldByAction = new LinkedHashMap<>();
        OffsetDateTime dataAsOf = null;

        for (var row : unique.values()) {
            if (row.scannedAt() != null && (dataAsOf == null || row.scannedAt().isBefore(dataAsOf))) dataAsOf = row.scannedAt();
            String verdict = effective(row);
            String severity = severity(row.severity());
            if (!"NOT_ANALYZED".equals(verdict)) judged++;
            if ("UNREACHABLE".equals(verdict)) {
                if ("CONFIRMED".equals(row.reviewState())) heldConfirmed++;
                else heldUnreviewed++;
                heldBySeverity.merge(severity, 1L, Long::sum);
                heldByAction.computeIfAbsent(action(row, upgradeTo.get(upgradeKey(row))), k -> new ArrayList<>()).add(row);
                continue;
            }
            if ("REACHABLE".equals(verdict) && ("CRITICAL".equals(severity) || "HIGH".equals(severity))) reachableHigh++;
            if ("UNKNOWN".equals(verdict)) unknown++;
            if ("NOT_ANALYZED".equals(verdict)) notAnalyzed++;
            severityCounts.merge(severity, 1L, Long::sum);
            String action = action(row, upgradeTo.get(upgradeKey(row)));
            byAction.computeIfAbsent(action, k -> new ArrayList<>()).add(row);
            findings.add(finding(row, verdict, severity, action, summaries.apply(row.vulnerabilityId())));
        }

        long newInPeriod = findings.stream().filter(f -> within(f.foundAt(), from, to)).count();
        long total = unique.size();
        boolean running = "RUNNING".equals(scope.appliedBasis());

        // 보류 건만 있는 패키지: 도달 불가라 리포트 조치에는 없지만, 수정 버전이 있으면 다음 정기 업데이트 때 같이 올릴 대상
        List<String> heldOnly = new ArrayList<>();
        heldByAction.forEach((title, rows) -> {
            if (byAction.containsKey(title) || !title.endsWith(" 이상으로 올리기")) return;
            var first = rows.get(0);
            heldOnly.add(upgradeName(first) + " " + first.componentVersion() + " → "
                    + upgradeTo.get(upgradeKey(first)) + " (" + rows.size() + "건)");
        });
        heldOnly.sort(Comparator.naturalOrder());

        var images = new LinkedHashSet<String>();
        unique.values().forEach(r -> images.add(appName(r.app()) + ": " + r.displayName()));
        List<ReportChapter.Item> items = List.of(
                new ReportChapter.Item("기준", running ? "운영에서 실행 중인 이미지(L1 수집)"
                        : "앱마다 최신 이미지 (L1 조회가 없어 실행 중인지 확인하지 못함)"),
                new ReportChapter.Item("대상 이미지", images.isEmpty() ? "—" : String.join(", ", images)),
                new ReportChapter.Item("판정 범위", "판정 " + judged + "건 / 전체 " + total + "건 (판정 전 " + notAnalyzed + "건)"),
                new ReportChapter.Item("도달 불가로 보류", (heldConfirmed + heldUnreviewed) + "건 = 사람 확정 " + heldConfirmed
                        + " · 검토 전 " + heldUnreviewed + severityText(heldBySeverity)),
                new ReportChapter.Item("보류 건만 있는 패키지 (다음 정기 업데이트 때 올리기)",
                        heldOnly.isEmpty() ? "없음" : String.join(" · ", heldOnly)),
                new ReportChapter.Item("실행 중인데 스캔 결과가 없는 이미지", scope.unscannedRunning() + "개"),
                new ReportChapter.Item("이미지 스캔이 없는 앱",
                        scope.appsWithoutImage().isEmpty() ? "없음" : String.join(", ", scope.appsWithoutImage())));

        List<ReportChapter.Remediation> remediations = byAction.entrySet().stream()
                .sorted(Comparator.comparingLong((Map.Entry<String, List<ReportRow>> e) -> -weight(e.getValue()))
                        .thenComparing(Map.Entry::getKey))
                .map(e -> remediation(e.getKey(), e.getValue(), heldByAction.getOrDefault(e.getKey(), List.of()).size()))
                .toList();

        List<String> notes = new ArrayList<>();
        if (!running) notes.add("L1 조회가 48시간 넘게 없어 앱마다 최신 이미지를 기준으로 셌다.");
        if (scope.unscannedRunning() > 0) {
            notes.add("실행 중인데 스캔 결과가 없는 이미지가 " + scope.unscannedRunning() + "개 있다. 그 앱은 최신 이미지로 셌다.");
        }

        return new ReportChapter(ReportPart.VULNERABILITY, dataAsOf,
                "운영 이미지에서 도달 가능 Critical·High " + reachableHigh + "건 · 확인 못 함 " + unknown + "건 (도달 불가 "
                        + (heldConfirmed + heldUnreviewed) + "건 보류)",
                "운영 이미지의 패키지×CVE (도달 불가 제외)",
                new ReportChapter.Metric("도달 가능 Critical·High", reachableHigh),
                items, severityCounts, findings, remediations,
                List.of(new ReportChapter.Link("취약점 요약", "/vulnerabilities"),
                        new ReportChapter.Link("도달 가능·확인 못 함 목록 (실행 중 이미지)",
                                FINDINGS_LINK + "?status=REACHABLE,UNKNOWN&deployment=RUNNING"),
                        new ReportChapter.Link("판정 규칙", "/vulnerabilities/rules")),
                List.of("범위: 운영에서 실행 중인 이미지의 최신 스캔(실행 중 스캔이 없는 앱은 최신 이미지). PR 검사와 레포 스캔은 넣지 않는다.",
                        "위험도는 스캐너(Trivy·Grype) 심각도 그대로다. 도달 판정은 리포트에 넣을지만 정한다: 도달 가능·확인 못 함·판정 전은 넣고, 도달 불가는 보류로 따로 센다.",
                        "사람이 확정한 판정이 도구 판정보다 우선한다. 잠정 판정은 도구 판정과 비교해 위험한 쪽을 쓴다.",
                        "발견일은 같은 앱에서 같은 패키지·CVE가 이미지에 처음 나온 때다(이미지가 바뀌어도 이어진다). 기한은 공통 기본값이다.",
                        "한계: 리플렉션·DI로 부르는 경로와 배포할 때만 넣는 환경 변수는 보지 못한다. 판정 데이터가 없는 CVE는 판정 전이다. 해결 건수는 아직 세지 않는다."),
                newInPeriod, null, notes.isEmpty() ? null : String.join(" ", notes));
    }

    /** 리포트가 쓰는 판정: 사람 확정 > 잠정(도구보다 위험할 때) > 도구 */
    static String effective(ReportRow row) {
        if ("CONFIRMED".equals(row.reviewState()) && row.reviewStatus() != null) return row.reviewStatus();
        if ("PROVISIONAL".equals(row.reviewState()) && row.reviewStatus() != null
                && rank(row.reviewStatus()) > rank(row.status())) return row.reviewStatus();
        return row.status();
    }

    private static int rank(String status) {
        return switch (status == null ? "" : status) {
            case "REACHABLE" -> 3;
            case "UNREACHABLE" -> 1;
            default -> 2;   // UNKNOWN, NOT_ANALYZED: 안전하다고 확인하지 못함
        };
    }

    static String severity(String scanner) {
        return scanner == null || "UNKNOWN".equals(scanner) ? "UNASSESSED" : scanner;
    }

    static ReportFinding finding(ReportRow row, String verdict, String severity, String action) {
        return finding(row, verdict, severity, action, null);
    }

    /**
     * 제목의 설명은 판정한 행이면 묶음이 넣은 한국어 요약(affectedFeature), 아니면 같은 CVE의 판정 데이터 요약(summaryKo:
     * 판정 데이터가 다른 패키지에만 있는 사본도 같은 취약점이다), 그것도 없으면 스캐너 제목(영어일 수 있음)
     */
    static ReportFinding finding(ReportRow row, String verdict, String severity, String action, String summaryKo) {
        String feature = row.affectedFeature() != null ? row.affectedFeature()
                : summaryKo != null ? summaryKo : shortTitle(row.vulnTitle(), row.componentName());
        String title = row.vulnerabilityId() + " · " + row.componentName() + " " + row.componentVersion() + about(feature);
        String asset = row.running() ? appName(row.app()) + " 운영 이미지 (" + row.displayName() + ")"
                : appName(row.app()) + " 최신 이미지 (실행 확인 안 됨, " + row.displayName() + ")";
        String location = row.componentName() + "@" + row.componentVersion()
                + (row.componentPath() == null ? "" : " (" + row.componentPath() + ")");
        OffsetDateTime found = row.firstFoundAt() != null ? row.firstFoundAt() : row.scannedAt();
        return new ReportFinding("REACH-F" + row.findingId(), title, severity, response(row, verdict), asset, location,
                evidence(row, verdict), found, null, false, "미지정", action, FINDINGS_LINK + "?finding=" + row.findingId());
    }

    /** 공통 상태 "미조치" + Reach 판정. Reach에는 조치 상태가 없다 */
    static String response(ReportRow row, String verdict) {
        return switch (verdict) {
            case "REACHABLE" -> "미조치 · 도달 가능" + ("CONFIRMED".equals(row.reviewState()) ? " (사람 확정)"
                    : row.l3Raised() && "REACHABLE".equals(row.status()) ? " (L3 실행 확인)" : "");
            case "UNKNOWN" -> "미조치 · 확인 못 함 (사람 검토 필요)";
            default -> "미조치 · 판정 전";   // 사유는 근거 칸에
        };
    }

    /** 판정 근거. 사람이 쓴 메모와 그 앞부분인 사람 판정 요약은 넣지 않는다 */
    static String evidence(ReportRow row, String verdict) {
        List<String> parts = new ArrayList<>();
        if ("CONFIRMED".equals(row.reviewState())) parts.add("사람 확정: " + STATUS.get(verdict));
        else if (!Objects.equals(verdict, row.status())) parts.add("잠정 판정: " + STATUS.get(verdict));
        if ("MANUAL".equals(row.method())) {
            parts.add("사람 판정 (메모는 대시보드)");
        } else if ("NOT_ANALYZED".equals(row.status())) {
            parts.add("판정 전: " + REASON.getOrDefault(row.notAnalyzedReason(), "판정하지 않음"));
        } else {
            parts.add("도구: " + STATUS.get(row.status()) + " (" + METHOD.getOrDefault(row.method(), row.method()) + ")"
                    + (row.summary() == null ? "" : " — " + cut(l2Reason(row), 120)));
        }
        // L3가 판정을 올렸을 때만 그렇게 쓴다. 올리지 않은 구간 실행은 사실만 적는다: 그 취약점의 조건(설정·기능 사용)을
        // 보여 주지 않는 CVE는 서버가 올리지 않고(규칙 데이터 l3), 이미 도달 가능이면 올릴 것이 없다
        if (row.l3Raised()) parts.add("L3: 실제 실행으로 판정을 올림");
        else if ("REGION".equals(row.l3Reached())) parts.add("L3: 취약 구간 실행됨 (판정은 그대로)");
        return String.join(" · ", parts);
    }

    /**
     * 도구 판정 요약. L3가 올린 판정이면 서버가 앞에 붙인 L3 문장("L3: …. L2 판정은 …였다: ")을 떼고 L2 판정의 이유만 쓴다.
     * L3로 올렸다는 사실은 근거 끝에 따로 적는다(앞 문장만으로 글자 수가 차 규칙의 이유가 잘리지 않게)
     */
    static String l2Reason(ReportRow row) {
        String summary = row.summary();
        if (!row.l3Raised() || summary == null || !summary.startsWith("L3: ")) return summary;
        int at = summary.indexOf("였다: ");
        return at < 0 ? summary : summary.substring(at + "였다: ".length());
    }

    private static String packageKey(ReportRow row) {
        return row.app() + "|" + row.componentName() + "|" + row.componentVersion();
    }

    /**
     * 함께 올라가는 묶음. Spring Boot 버전 속성이 같은 jar(tomcat-embed-core·websocket, Jackson 2의 core·databind)는
     * 속성 하나를 바꾸면 같이 올라가므로 조치 하나로 묶는다. 그 밖은 패키지마다
     */
    private static String upgradeKey(ReportRow row) {
        String property = bootProperty(row);
        return property == null ? packageKey(row) : row.app() + "|" + property + "|" + row.componentVersion();
    }

    /** 조치 제목의 이름: 묶음이면 Tomcat·Jackson, 아니면 패키지 이름 */
    static String upgradeName(ReportRow row) {
        String property = bootProperty(row);
        if (property == null) return row.componentName();
        return property.startsWith("tomcat") ? "Tomcat" : "Jackson";
    }

    /**
     * 묶음(upgradeKey)마다 올릴 버전: 그 묶음 Finding 각각의 수정 버전 중 가장 높은 것.
     * CVE마다 수정 버전이 달라도(11.0.25, 11.0.27) 한 번 올리면 모두 고쳐지므로 조치 하나로 묶는다.
     * 도달 불가로 보류한 건도 넣는다: 어차피 올리는 김에 보류한 Critical까지 고치는 버전을 권한다
     */
    static Map<String, String> upgradeTo(Collection<ReportRow> rows) {
        Map<String, String> result = new LinkedHashMap<>();
        for (var row : rows) {
            String fix = fixVersion(row.componentVersion(), row.fixedVersions());
            if (fix != null) result.merge(upgradeKey(row), fix, (a, b) -> compare(a, b) >= 0 ? a : b);
        }
        return result;
    }

    /** 공통 조치에 묶이는 이름. ReportComposer가 action에 이 제목이 들어 있는 Finding을 그 조치에 묶는다 */
    static String action(ReportRow row, String upgradeTo) {
        if ("OS_PACKAGE".equals(row.notAnalyzedReason())) return BASE_IMAGE;
        String fix = fixVersion(row.componentVersion(), row.fixedVersions());
        if (fix == null) return row.componentName() + " 수정 버전 없음: 완화책 검토";
        return upgradeName(row) + " " + (upgradeTo != null ? upgradeTo : fix) + " 이상으로 올리기";
    }

    static String action(ReportRow row) {
        return action(row, null);
    }

    /** 설치 버전과 같은 줄(앞 두 숫자가 같은: 11.0.24 → 11.0.x, 1.81 → 1.81.x)의 수정 버전, 없으면 설치 버전보다 큰 것 중 가장 작은 것 */
    static String fixVersion(String installed, List<String> fixed) {
        if (fixed == null || fixed.isEmpty()) return null;
        var later = fixed.stream().filter(v -> compare(v, installed) > 0).sorted(ReachReportChapterProvider::compare).toList();
        if (later.isEmpty()) return null;
        String line = line(installed);
        return later.stream().filter(v -> line(v).equals(line)).findFirst().orElse(later.get(0));
    }

    private static String line(String version) {
        String[] parts = version.split("[.\\-+_]");
        return parts.length < 2 ? parts[0] : parts[0] + "." + parts[1];
    }

    static int compare(String a, String b) {
        String[] x = a.split("[.\\-+_]"), y = b.split("[.\\-+_]");
        for (int i = 0; i < Math.max(x.length, y.length); i++) {
            String p = i < x.length ? x[i] : "0", q = i < y.length ? y[i] : "0";
            int c = p.matches("\\d+") && q.matches("\\d+") ? Long.compare(Long.parseLong(p), Long.parseLong(q)) : p.compareTo(q);
            if (c != 0) return c;
        }
        return 0;
    }

    static ReportChapter.Remediation remediation(String title, List<ReportRow> rows, int heldResolved) {
        long critical = rows.stream().filter(r -> "CRITICAL".equals(r.severity())).count();
        long high = rows.stream().filter(r -> "HIGH".equals(r.severity())).count();
        var apps = new LinkedHashSet<String>();
        rows.forEach(r -> apps.add(appName(r.app())));
        String impact = "Critical " + critical + " · High " + high + " · 그 밖 " + (rows.size() - critical - high) + "건 ("
                + String.join("·", apps) + ")" + (heldResolved > 0 ? " · 도달 불가로 보류한 " + heldResolved + "건도 함께 해소" : "");
        String how;
        if (BASE_IMAGE.equals(title)) {
            how = "Dockerfile의 베이스 이미지를 최신 digest로 다시 받고 OS 패키지를 갱신한 뒤 이미지를 다시 빌드·배포하세요.";
        } else if (title.endsWith("완화책 검토")) {
            how = "아직 수정 버전이 없습니다. 권고문의 완화책(기능 끄기, 입력 제한)을 적용하고, 수정 버전이 나오면 올리세요.";
        } else {
            String property = bootProperty(rows.get(0));
            how = property == null
                    ? "빌드 파일의 의존성 버전을 올리고 이미지를 다시 빌드·배포하세요. 다른 라이브러리가 끌어온 의존성이면 그 라이브러리를 올리거나 버전을 고정하세요."
                    : "Spring Boot가 버전을 정하는 라이브러리입니다. 이 버전을 담은 Spring Boot 패치로 올리고, 아직 없으면 빌드 파일에서 "
                            + property + " 속성으로 버전을 고정한 뒤 이미지를 다시 빌드·배포하세요(다음 Spring Boot 업그레이드 때 고정 해제).";
        }
        return new ReportChapter.Remediation(title, how, impact, FINDINGS_LINK);
    }

    /** Spring Boot 의존성 관리 속성 이름 (spring-boot-dependencies). 모르는 패키지는 null */
    static String bootProperty(ReportRow row) {
        String name = row.componentName() == null ? "" : row.componentName();
        String version = row.componentVersion() == null ? "" : row.componentVersion();
        if (name.startsWith("tomcat-embed-")) return "tomcat.version";
        if (name.startsWith("jackson-")) return version.startsWith("2.") ? "jackson-2-bom.version" : "jackson-bom.version";
        return null;
    }

    /**
     * 스캐너 제목 앞의 패키지 좌표 덧붙임을 걷어 낸다. Trivy(Red Hat) 제목은
     * "com.fasterxml.jackson.core/jackson-databind: tools.jackson.core/jackson-databind: Jackson-databind: Denial of …"처럼
     * 좌표를 여러 번 앞에 붙인다. 공백 없는 앞 조각이 패키지 이름(앞부분)을 담고 있을 때만 뗀다
     */
    static String shortTitle(String title, String component) {
        if (title == null || component == null || component.isBlank()) return title;
        String key = component.toLowerCase(java.util.Locale.ROOT).split("-")[0];
        String text = title.strip();
        while (true) {
            int colon = text.indexOf(": ");
            if (colon <= 0) break;
            String head = text.substring(0, colon);
            if (head.contains(" ") || !head.toLowerCase(java.util.Locale.ROOT).contains(key)) break;
            text = text.substring(colon + 2).strip();
        }
        return text.isEmpty() ? title : text;
    }

    private static long weight(List<ReportRow> rows) {
        return rows.stream().mapToLong(r -> switch (r.severity()) {
            case "CRITICAL" -> 1000;
            case "HIGH" -> 100;
            case "MEDIUM" -> 10;
            default -> 1;
        }).sum();
    }

    private static String severityText(Map<String, Long> counts) {
        if (counts.isEmpty()) return "";
        List<String> parts = new ArrayList<>();
        for (var s : SEVERITIES) {
            if (counts.getOrDefault(s, 0L) > 0) parts.add(label(s) + " " + counts.get(s));
        }
        return " (" + String.join(" · ", parts) + ")";
    }

    private static String label(String severity) {
        return switch (severity) {
            case "CRITICAL" -> "Critical";
            case "HIGH" -> "High";
            case "MEDIUM" -> "Medium";
            case "LOW" -> "Low";
            default -> "미평가";
        };
    }

    private static String about(String text) {
        return text == null || text.isBlank() ? "" : ": " + cut(text, 60);
    }

    private static String appName(String app) {
        return app == null ? "앱 미지정" : app;
    }

    private static String cut(String text, int max) {
        String one = text.replaceAll("\\s+", " ").strip();
        return one.length() <= max ? one : one.substring(0, max - 1) + "…";
    }

    private static boolean within(OffsetDateTime at, OffsetDateTime from, OffsetDateTime to) {
        return at != null && !at.isBefore(from) && at.isBefore(to);
    }
}
