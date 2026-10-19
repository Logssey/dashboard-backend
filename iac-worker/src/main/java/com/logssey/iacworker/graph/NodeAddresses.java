package com.logssey.iacworker.graph;

import java.util.Map;

/** 쿠버네티스 노드 이름 → InternalIP. Cartography KubernetesNode 에는 IP 가 없어 따로 받는다 (10/13 확인). */
public interface NodeAddresses {
    Map<String, String> byNodeName();
}
