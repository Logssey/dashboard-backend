package com.logssey.iacworker.analysis;

import java.util.List;
import java.util.Map;

import com.logssey.iacworker.graph.GraphEnricher;

/**
 * 분석에 쓰는 그래프의 메모리 사본. 원본 Neo4j 는 바꾸지 않는다 (PR 분석은 사본에서, database-schema).
 *
 * @param nodes     노드 ID → 노드
 * @param edges     경로 관계 (CAN_REACH, ORIGIN, EXPOSE, HAS_CREDS_OF, IS_INSTANCE, CAN_READ)
 * @param instances EC2 노드 ID → IMDS 설정과 역할
 * @param roles     역할 ID → 이름과 붙은 정책
 * @param managed   관리형 정책 ARN → 정책 (그래프에 있는 것만)
 */
public record GraphSnapshot(Map<String, Node> nodes, List<Edge> edges, Map<String, Instance> instances,
                            Map<String, Role> roles, Map<String, Policy> managed) {

    public record Node(String id, String kind, String name, String arn, Integer tier, Long dataAssetId) {

        GraphEnricher.Hop hop() {
            return new GraphEnricher.Hop(kind, id, name);
        }
    }

    public record Edge(String from, String type, String to) {
    }

    public record Instance(String nodeId, String instanceId, String httpTokens, String httpEndpoint,
                           List<String> roleIds) {

        boolean exposesCredentials(String tokens) {
            return "optional".equals(tokens) && !"disabled".equals(httpEndpoint);
        }
    }

    public record Role(String id, String name, Map<String, Policy> policies) {
    }
}
