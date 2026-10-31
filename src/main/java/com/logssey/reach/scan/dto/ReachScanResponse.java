package com.logssey.reach.scan.dto;

import java.time.OffsetDateTime;
import java.util.Map;

import tools.jackson.databind.JsonNode;

/** API-03 스캔 상태·요약 (Reach API 명세 3-1 Scan, 3-2 Target) */
public record ReachScanResponse(
        long id, String scanStatus, String trigger, Long rescanOf,    // rescanOf: 저장된 SBOM을 다시 쓴 원래 스캔
        Target target,
        JsonNode stages, JsonNode tools, JsonNode analysis,           // DB의 JSONB를 그대로
        Counts counts, Failure failure, RequestedBy requestedBy,      // counts는 SUCCEEDED, failure는 FAILED일 때만
        OffsetDateTime createdAt, OffsetDateTime startedAt, OffsetDateTime finishedAt) {

    /** repo는 type=REPO, image는 type=IMAGE일 때만 채운다 */
    public record Target(long id, String type, String app, Repo repo, Image image,
                         String sourceTree, String displayName) {}

    public record Repo(String name, String path, String commit) {}

    public record Image(String repository, String digest, String revision, OffsetDateTime createdAt) {}

    /** 그 스캔이 낸 도구 판정 개수. 값은 0까지 채운다 */
    public record Counts(long total, Map<String, Long> bySeverity, Map<String, Long> byStatus,
                         Map<String, Long> byReviewState) {}

    public record Failure(String code, String stage, String message) {}

    /** kind(USER / CI / SYSTEM)는 명세에 없어 더했다. USER면 userId, CI면 repository·subject */
    public record RequestedBy(String kind, Long userId, String repository, String subject) {}

    /** record는 값을 못 바꿔서, counts만 바꾼 새 record를 만든다 */
    public ReachScanResponse withCounts(Counts counts) {
        return new ReachScanResponse(id, scanStatus, trigger, rescanOf, target, stages, tools, analysis,
                counts, failure, requestedBy, createdAt, startedAt, finishedAt);
    }
}
