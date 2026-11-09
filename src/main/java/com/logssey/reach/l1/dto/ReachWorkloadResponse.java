package com.logssey.reach.l1.dto;

import java.time.OffsetDateTime;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * API-07 한 항목 (명세 3-6 Workload). 워크로드 안의 (컨테이너, digest) 하나다.
 * id는 업로드마다 새로 매겨진다. app은 정하지 못하면 null로 준다
 */
public record ReachWorkloadResponse(
        long id,
        String cluster,
        String namespace,
        String kind,
        String name,
        String container,
        String app,
        Image image,
        Replicas replicas,
        String deployment,
        ScanMatch scanMatch,
        OffsetDateTime observedAt,
        String source) {

    /** revision(태그)은 태그가 없으면 뺀다 */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Image(String repository, String digest, String revision) {
    }

    public record Replicas(int ready) {
    }

    /** NO_SCAN이면 status만, MISMATCH면 matchedBy를 뺀다 */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ScanMatch(String status, Long scanId, String matchedBy) {
    }
}
