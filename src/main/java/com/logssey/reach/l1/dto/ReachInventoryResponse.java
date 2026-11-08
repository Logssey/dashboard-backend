package com.logssey.reach.l1.dto;

import java.time.OffsetDateTime;

/** L1 업로드 결과. workloads는 받은 워크로드 수, findingsUpdated는 이번 재계산으로 deployment가 바뀐 Finding 수 */
public record ReachInventoryResponse(String cluster, String namespace, OffsetDateTime observedAt,
                                     int workloads, int findingsUpdated) {}
