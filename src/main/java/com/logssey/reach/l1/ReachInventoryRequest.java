package com.logssey.reach.l1;

import java.time.OffsetDateTime;
import java.util.List;

/**
 * L1 수집 결과 (수집기 inventory.jq 출력과 같은 모양).
 * 값 검사는 Service의 validate()가 한다 (record 생성자에서 던지면 Jackson이 다른 예외로 감싼다).
 */
public record ReachInventoryRequest(String cluster, String namespace, OffsetDateTime observedAt,
                                    List<Workload> workloads) {

    public record Workload(String kind, String name, List<Container> containers) {}

    /** readyReplicas는 이 digest를 돌리는 Ready 파드 수. 롤아웃 중이면 digest마다 다르다 */
    public record Container(String name, String image, String imageDigest, Integer readyReplicas) {}
}