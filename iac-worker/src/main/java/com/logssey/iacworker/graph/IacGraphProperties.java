package com.logssey.iacworker.graph;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 자산 그래프(Neo4j)와 보강 입력.
 * nodeAddressesFile: 쿠버네티스 노드 이름 → InternalIP JSON. 클러스터 안 워커는 S4 에서 k8s API 로 바꾼다.
 */
@ConfigurationProperties("logssey.iac.graph")
public record IacGraphProperties(String uri, String username, String password, String awsProfile,
                                 String nodeAddressesFile) {
}
