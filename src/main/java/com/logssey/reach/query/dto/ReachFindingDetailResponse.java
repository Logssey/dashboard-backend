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

    /** 사람 검토. 아직 검토 전이면 reviewer는 null이다. history는 include=reviewHistory일 때만 */
    public record Review(String reviewState, String status, String note, Reviewer reviewer, OffsetDateTime reviewedAt,
                         int version, boolean disagreesWithTool, JsonNode proposal, CarriedFrom carriedFrom,
                         String resetReason, List<History> history) {}

    public record Reviewer(long id, String name) {}

    /** 이 검토를 이어받은 이전 Finding. reviewedAt은 그 Finding의 검토 시각 */
    public record CarriedFrom(long findingId, long scanId, OffsetDateTime reviewedAt) {}

    /** 검토 이력 한 줄. changeKind는 명세에 없어 더했다: HUMAN(사람) / CARRIED(이어받음) / RESET(서버가 되돌림) */
    public record History(String reviewState, String status, String note, JsonNode proposal, Reviewer reviewer,
                          OffsetDateTime reviewedAt, int version, String changeKind) {}

    /** record는 값을 못 바꿔서, review.history만 채운 새 record를 만든다 */
    public ReachFindingDetailResponse withReviewHistory(List<History> history) {
        var r = review;
        return new ReachFindingDetailResponse(id, scanId, targetId, component, vulnerability, deployment, sources,
                verdict, new Review(r.reviewState(), r.status(), r.note(), r.reviewer(), r.reviewedAt(), r.version(),
                        r.disagreesWithTool(), r.proposal(), r.carriedFrom(), r.resetReason(), history),
                upgrade, sameCveFindings, firstSeenAt, lastSeenAt);
    }
}