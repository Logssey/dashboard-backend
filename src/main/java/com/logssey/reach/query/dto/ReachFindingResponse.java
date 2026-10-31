package com.logssey.reach.query.dto;

import java.time.OffsetDateTime;
import java.util.List;

import tools.jackson.databind.JsonNode;

/** API-04 목록 한 행. 필드 이름은 프론트 /src/api/reach.ts 의 ReachFindingListItem 과 같다 */
public record ReachFindingResponse(
        long id,
        long scanId,
        long targetId,
        Component component,
        Vulnerability vulnerability,
        String deployment,
        Verdict verdict,
        Review review,
        OffsetDateTime firstSeenAt) {

    public record Component(String purl, String name, String version) {
    }

    public record Vulnerability(String id, String severity, List<String> fixedVersions) {
    }

    public record Verdict(String status, String method, String summary, String notAnalyzedReason) {
    }

    public record Review(String reviewState, boolean disagreesWithTool, JsonNode proposal, String resetReason) {
    }
}