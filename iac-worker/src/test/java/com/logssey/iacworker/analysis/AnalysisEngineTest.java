package com.logssey.iacworker.analysis;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

class AnalysisEngineTest {

    private static final JsonMapper MAPPER = JsonMapper.builder().build();
    private static final String SECRET_ARN = "arn:aws:secretsmanager:ap-northeast-1:1:secret:db";

    /**
     * 인터넷 → CloudFront → NLB → A → 역할 → 시크릿 (5 홉) 이 이미 열려 있을 때,
     * 인터넷에 바로 열린 LB 뒤의 B 에 IMDSv1 을 켜면 같은 시크릿까지 4 홉 길이 생긴다 → 단축.
     */
    @Test
    void shorterRouteToAlreadyReachableDataIsShortenedNotAdded() {
        var graph = new GraphSnapshot(
                Map.of("internet", node("internet", "Internet", null), "cf", node("cf", "AWSCloudFrontDistribution", null),
                        "nlb", node("nlb", "AWSLoadBalancerV2", null), "lb2", node("lb2", "AWSLoadBalancerV2", null),
                        "i-a", node("i-a", "AWSEC2Instance", null), "i-b", node("i-b", "AWSEC2Instance", null),
                        "role", node("role", "AWSRole", null), "secret", new GraphSnapshot.Node("secret",
                                "AWSSecretsManagerSecret", "db", SECRET_ARN, 1, 1L)),
                List.of(edge("internet", "CAN_REACH", "cf"), edge("cf", "ORIGIN", "nlb"), edge("nlb", "EXPOSE", "i-a"),
                        edge("i-a", "HAS_CREDS_OF", "role"), edge("role", "CAN_READ", "secret"),
                        edge("internet", "CAN_REACH", "lb2"), edge("lb2", "EXPOSE", "i-b")),
                Map.of("i-a", new GraphSnapshot.Instance("i-a", "i-a", "optional", "enabled", List.of("role")),
                        "i-b", new GraphSnapshot.Instance("i-b", "i-b", "required", "enabled", List.of("role"))),
                Map.of("role", new GraphSnapshot.Role("role", "node", Map.of())), Map.of());
        var plan = MAPPER.readTree("""
                {"format_version":"1.2","resource_changes":[{"address":"aws_instance.b","type":"aws_instance",
                  "change":{"actions":["update"],"before":{"id":"i-b","metadata_options":[{"http_tokens":"required"}]},
                            "after":{"id":"i-b","metadata_options":[{"http_tokens":"optional"}]}}}]}
                """);

        var result = new AnalysisEngine((documents, action, resource) -> "allowed").analyze(graph, plan, Set.of());

        assertThat(result.changes()).hasSize(1);
        var change = result.changes().getFirst();
        assertThat(change.change() + "|" + change.ruleId() + "|" + change.severity() + "|" + change.hops().size())
                .isEqualTo("SHORTENED|path.shortened|MEDIUM|5");
        assertThat(change.cause().address()).isEqualTo("aws_instance.b");
        assertThat(result.verdict()).isEqualTo("WARN");
    }

    private static GraphSnapshot.Node node(String id, String kind, Integer tier) {
        return new GraphSnapshot.Node(id, kind, id, null, tier, null);
    }

    private static GraphSnapshot.Edge edge(String from, String type, String to) {
        return new GraphSnapshot.Edge(from, type, to);
    }
}
