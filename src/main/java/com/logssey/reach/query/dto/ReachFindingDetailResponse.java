package com.logssey.reach.query.dto;

import java.time.OffsetDateTime;
import java.util.List;

import tools.jackson.databind.JsonNode;

/** API-05 상세
 * 필드 이름은 프론트 /src/api/reach.ts의 ReachFindingDetail 과 같다.
 */
public record ReachFindingDetailResponse(
        long id, long scanId, long targetId,
        Component component, Vulnerability vulnerability,
        String deployment, List<String> sources,            // 탐지한 스캐너 (TRIVY, GRYPE)
        Verdict verdict, Review review,
        JsonNode upgrade, List<Long> sameCveFindings,       // 같은 스캔에서 CVE가 같은 다른 Finding id
        OffsetDateTime firstSeenAt, OffsetDateTime lastSeenAt) {

    public record Component(String purl, String name, String version, String ecosystem) {}

    public record Vulnerability(String id, String severity, String severityNote, String title,
                                String affectedFeature, List<String> fixedVersions) {}

    /** 현재 판정. callgraph·engine은 DB의 JSONB를 그대로, evidence는 ord 순서 배열 */
    public record Verdict(String status, String method, String summary, String notAnalyzedReason, String ruleId,
                          JsonNode callgraph, JsonNode evidence, OffsetDateTime analyzedAt, JsonNode engine) {}

    /** 사람 검토. 아직 검토 전이면 reviewer는 null이다. carriedFrom은 1단계에서 뺐다 */
    public record Review(String reviewState, String status, String note, Reviewer reviewer, OffsetDateTime reviewedAt,
                         int version, boolean disagreesWithTool, JsonNode proposal, String resetReason) {}

    public record Reviewer(long id, String name) {}
}