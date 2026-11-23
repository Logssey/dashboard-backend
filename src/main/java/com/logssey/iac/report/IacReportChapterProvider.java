package com.logssey.iac.report;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.logssey.iac.query.IacDriftResponse;
import com.logssey.iac.query.IacPathDetailResponse;
import com.logssey.iac.query.IacPathResponse;
import com.logssey.iac.query.IacQueryService;
import com.logssey.iac.query.IacRemediationResponse;
import com.logssey.report.ReportChapter;
import com.logssey.report.ReportChapterProvider;
import com.logssey.report.ReportFinding;
import com.logssey.report.ReportPart;

import org.springframework.stereotype.Component;

/**
 * 통합 리포트의 IaC 장. 대시보드 조회 서비스가 주는 값만 읽는다.
 * 경로 단계는 종류 이름만 쓰고 ARN·리소스 이름은 넣지 않는다 (양식 "표기·보안 규칙").
 */
@Component
public class IacReportChapterProvider implements ReportChapterProvider {

    static final int PAGE = 100;

    private static final Map<String, String> HOP_LABELS = Map.ofEntries(
            Map.entry("Internet", "인터넷"), Map.entry("AWSCloudFrontDistribution", "CloudFront"),
            Map.entry("AWSLoadBalancerV2", "로드밸런서"), Map.entry("AWSEC2Instance", "EC2"),
            Map.entry("KubernetesNode", "노드"), Map.entry("KubernetesPod", "파드"), Map.entry("AWSRole", "역할"),
            Map.entry("AWSUser", "사용자"), Map.entry("AWSSecretsManagerSecret", "시크릿"),
            Map.entry("AWSS3Bucket", "S3 버킷"), Map.entry("AWSRDSInstance", "RDS"));

    private static final Map<String, String> TARGET_LABELS = Map.of(
            "RDS", "DB(RDS)", "SECRET", "시크릿", "S3", "S3 버킷", "TFSTATE", "tfstate 버킷");

    /** 끊을 지점 (백엔드 action 값) → 한 줄 근거와 조치 */
    private static final Map<String, String[]> CUTS = Map.of(
            "IMDSV2_REQUIRED", new String[]{"EC2가 IMDSv1을 허용해 역할 자격 증명을 꺼낼 수 있음", "EC2 메타데이터를 IMDSv2로만 받기"},
            "SECRETS_READ_SCOPE", new String[]{"역할이 계정의 모든 시크릿을 읽을 수 있음", "역할의 시크릿 읽기 범위 좁히기"},
            "TFSTATE_BUCKET_POLICY", new String[]{"tfstate 버킷 정책이 이 역할의 읽기를 막지 않음", "State 버킷 읽기 주체 줄이기"});

    static final String POLICY_URL = "https://github.com/Logssey/infrastructure/tree/main/policy";

    private static final Map<String, String> HOW = Map.of(
            "IMDSV2_REQUIRED", "compute 모듈의 변수 imds_tokens 를 \"required\" 로 바꾸면 인스턴스에서 역할 자격 증명을 꺼내는 관계가 끊깁니다.",
            "SECRETS_READ_SCOPE", "secretsmanager:GetSecretValue 의 Resource 를 \"*\" 대신 이 역할이 실제로 쓰는 시크릿 ARN 으로 제한하세요.",
            "TFSTATE_BUCKET_POLICY", "tfstate 버킷 정책에서 plan·apply 역할 외의 s3:GetObject 를 거부하세요.");

    private final IacQueryService query;

    public IacReportChapterProvider(IacQueryService query) {
        this.query = query;
    }

    @Override
    public ReportPart part() {
        return ReportPart.IAC;
    }

    @Override
    public ReportChapter chapter(OffsetDateTime from, OffsetDateTime to, String loginId) {
        var summary = query.summary(loginId);
        var open = allPaths("OPEN", loginId);
        var closed = allPaths("CLOSED", loginId);
        var drifts = query.drifts("OPEN", loginId);
        var remediations = query.remediations(loginId);

        List<ReportFinding> findings = new ArrayList<>();
        open.forEach(p -> findings.add(pathFinding(p)));
        drifts.forEach(d -> findings.add(driftFinding(d)));

        long tier1 = summary.metrics().tier1OpenPaths();
        long cutPoints = remediations.stream().filter(r -> r.tier1PathsCut() > 0).count();
        Map<String, Long> counts = new LinkedHashMap<>(summary.severityCounts());
        counts.put("UNASSESSED", 0L);

        long newInPeriod = open.stream().filter(p -> within(p.firstSeenAt(), from, to)).count()
                + drifts.stream().filter(d -> within(d.firstSeenAt(), from, to)).count();
        long resolvedInPeriod = closed.stream().filter(p -> within(p.lastSeenAt(), from, to)).count();
        long unassigned = open.size() + drifts.stream().filter(d -> d.assigneeUserId() == null).count();

        List<ReportChapter.Remediation> actions = new ArrayList<>();
        remediations.forEach(r -> actions.add(remediation(r)));
        if (!drifts.isEmpty()) {
            actions.add(new ReportChapter.Remediation("드리프트 정리",
                    "코드 밖에서 바뀐 설정을 코드에 반영하거나, 다음 apply 로 코드 상태로 되돌리세요.",
                    "드리프트 " + drifts.size() + "건", "/iac"));
        }

        return new ReportChapter(ReportPart.IAC, summary.graphAsOf(),
                "1등급 데이터까지 열린 경로 " + tier1 + "개, 끊을 지점 " + cutPoints + "곳",
                "열린 경로 · 매일 점검 발견 건",
                new ReportChapter.Metric("1등급 데이터까지 열린 경로", tier1),
                List.of(new ReportChapter.Item("자산 그래프 기준", format(summary.graphAsOf())),
                        new ReportChapter.Item("마지막 전체 점검", format(summary.lastFullCheckAt())),
                        new ReportChapter.Item("열린 경로 (전체 등급)", summary.metrics().openPaths() + "개"),
                        new ReportChapter.Item("드리프트", drifts.size() + "건"),
                        new ReportChapter.Item("담당 미지정", unassigned + "건")),
                counts, findings, actions,
                List.of(new ReportChapter.Link("IaC 보안 화면 (열린 경로·끊을 지점)", "/iac"),
                        new ReportChapter.Link("plan 전 검사 규칙", POLICY_URL)),
                List.of("위험도는 노출 × 데이터 등급으로 정한다. 인터넷에서 자격 증명을 얻어 1등급 데이터를 읽는 연결이 완성되면 Critical.",
                        "PR이 1등급 데이터까지 새 경로를 열고 AWS IAM 시뮬레이터가 허용을 확인하면 차단 판정한다.",
                        "plan 중 실행되는 코드·공급망 변조는 plan 전 검사에서 차단 판정한다."),
                newInPeriod, resolvedInPeriod,
                summary.graphStale() ? "자산 그래프가 24시간 넘게 갱신되지 않았다." : null);
    }

    /** 대시보드 IaC 화면의 "제안 조치"와 같은 문구 */
    static ReportChapter.Remediation remediation(IacRemediationResponse r) {
        String how = HOW.getOrDefault(r.action(), "IaC 화면의 경로 상세에서 끊을 관계를 확인하세요.");
        String impact = "STATE".equals(r.source()) ? "tfstate 를 읽을 수 있는 주체 감소"
                : "열린 경로 " + r.pathsCut() + "개 닫힘 (1등급 " + r.tier1PathsCut() + "개)";
        return new ReportChapter.Remediation(cutTitle(r), how, impact, "/iac");
    }

    private List<IacPathResponse> allPaths(String status, String loginId) {
        List<IacPathResponse> all = new ArrayList<>();
        Long cursor = null;
        do {
            var page = query.paths(status, null, cursor, PAGE, loginId);
            all.addAll(page.items());
            cursor = page.nextCursor();
        } while (cursor != null);
        return all;
    }

    static ReportFinding pathFinding(IacPathResponse path) {
        String target = TARGET_LABELS.getOrDefault(path.target().kind(), path.target().kind());
        var cuts = cutActions(path);
        String evidence = cuts.isEmpty() ? "인터넷에서 데이터까지 " + path.length() + "단계로 이어짐"
                : cuts.stream().map(a -> CUTS.get(a)[0]).collect(Collectors.joining(", "));
        String action = cuts.isEmpty() ? "경로 상세에서 끊을 관계 확인"
                : "끊을 지점: " + cuts.stream().map(a -> CUTS.get(a)[1]).collect(Collectors.joining(" 또는 "));
        return new ReportFinding("IAC-P" + path.pathId(), "인터넷에서 " + target + "까지 열린 공격 경로",
                path.severity(), "미조치 · 열린 경로", target + ", " + path.tier() + "등급", hops(path), evidence,
                path.firstSeenAt(), null, false, "미지정", action, "/iac");
    }

    static ReportFinding driftFinding(IacDriftResponse drift) {
        String attrs = drift.attributes() == null || drift.attributes().isEmpty() ? "—" : String.join(", ", drift.attributes());
        return new ReportFinding("IAC-D" + drift.findingId(), "코드 밖에서 바뀐 인프라 (드리프트)", drift.severity(),
                "미조치 · 드리프트", null, drift.address(), "바뀐 속성: " + attrs, drift.firstSeenAt(), null, false,
                drift.assigneeUserId() == null ? "미지정" : "지정됨", "드리프트 정리: 코드와 실제를 맞추거나 바뀐 내용을 코드에 반영", "/iac");
    }

    /** 경로 단계를 종류 이름으로만 (예: 인터넷 → CloudFront → 로드밸런서 → EC2 → 역할 → 시크릿) */
    static String hops(IacPathResponse path) {
        List<String> names = new ArrayList<>();
        path.hops().forEach(h -> names.add(HOP_LABELS.getOrDefault(h.path("kind").asString(""), h.path("kind").asString("?"))));
        return String.join(" → ", names);
    }

    static List<String> cutActions(IacPathResponse path) {
        return IacQueryService.cutPoints(path).stream().map(IacPathDetailResponse.CutPoint::action)
                .filter(CUTS::containsKey).distinct().toList();
    }

    private static String cutTitle(IacRemediationResponse r) {
        var cut = CUTS.get(r.action());
        return cut == null ? r.action() : cut[1];
    }

    private static boolean within(OffsetDateTime at, OffsetDateTime from, OffsetDateTime to) {
        return at != null && !at.isBefore(from) && at.isBefore(to);
    }

    private static String format(OffsetDateTime at) {
        return at == null ? "— (기록 없음)" : at.atZoneSameInstant(java.time.ZoneId.of("Asia/Seoul"))
                .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'KST'"));
    }
}
