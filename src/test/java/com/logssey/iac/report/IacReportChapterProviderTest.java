package com.logssey.iac.report;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.OffsetDateTime;
import java.util.List;

import com.logssey.iac.query.IacDriftResponse;
import com.logssey.iac.query.IacPathResponse;

import org.junit.jupiter.api.Test;

import tools.jackson.databind.json.JsonMapper;

class IacReportChapterProviderTest {

    private static final OffsetDateTime SEEN = OffsetDateTime.parse("2026-11-19T03:03:00+09:00");

    private static IacPathResponse secretPath() {
        var hops = JsonMapper.builder().build().readTree("""
                [{"kind":"Internet","id":"internet","name":"Internet"},
                 {"kind":"AWSCloudFrontDistribution","id":"arn:aws:cloudfront::123456789012:distribution/E1","name":"E1"},
                 {"kind":"AWSLoadBalancerV2","id":"arn:aws:elasticloadbalancing:ap-northeast-1:123456789012:loadbalancer/net/logssey-prod-nlb-public/1","name":"logssey-prod-nlb-public"},
                 {"kind":"AWSEC2Instance","id":"i-0c18628fa30035aa9","name":"i-0c18628fa30035aa9"},
                 {"kind":"AWSRole","id":"arn:aws:iam::123456789012:role/logssey-prod-role-node","name":"logssey-prod-role-node"},
                 {"kind":"AWSSecretsManagerSecret","id":"arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:logssey/dashboard/ai/claude-api-key","name":"logssey/dashboard/ai/claude-api-key"}]
                """);
        return new IacPathResponse(7, "OPEN", 1, "CRITICAL", 5, hops,
                new IacPathResponse.Target("arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:logssey/dashboard/ai/claude-api-key", "SECRET"),
                SEEN, SEEN);
    }

    @Test
    void 경로는_종류_이름만_쓰고_식별자를_넣지_않는다() {
        var finding = IacReportChapterProvider.pathFinding(secretPath());

        assertThat(finding.location()).isEqualTo("인터넷 → CloudFront → 로드밸런서 → EC2 → 역할 → 시크릿");
        var all = String.join("|", finding.id(), finding.title(), finding.asset(), finding.location(),
                finding.evidence(), finding.action());
        assertThat(all).doesNotContain("i-0c18", "123456789012", "claude-api-key", "logssey-prod", "arn:");
    }

    @Test
    void 끊을_지점이_근거와_조치가_된다() {
        var finding = IacReportChapterProvider.pathFinding(secretPath());

        assertThat(finding.title()).isEqualTo("인터넷에서 시크릿까지 열린 공격 경로");
        assertThat(finding.asset()).isEqualTo("시크릿, 1등급");
        assertThat(finding.evidence()).contains("IMDSv1", "모든 시크릿");
        assertThat(finding.action()).isEqualTo("끊을 지점: EC2 메타데이터를 IMDSv2로만 받기 또는 역할의 시크릿 읽기 범위 좁히기");
        assertThat(finding.foundAt()).isEqualTo(SEEN);
        assertThat(finding.dueAt()).as("기한은 공통 기능이 기본값으로 채운다").isNull();
    }

    @Test
    void 드리프트는_바뀐_속성_이름만_쓴다() {
        var drift = new IacDriftResponse(3, "drift.high", "WARN", "HIGH", "module.lb.aws_lb_listener.public", "UPDATE",
                List.of("mutual_authentication"), "OPEN", null, 1, SEEN, SEEN);

        var finding = IacReportChapterProvider.driftFinding(drift);

        assertThat(finding.evidence()).isEqualTo("바뀐 속성: mutual_authentication");
        assertThat(finding.assignee()).isEqualTo("미지정");
        assertThat(finding.severity()).isEqualTo("HIGH");
    }
}
