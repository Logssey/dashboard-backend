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
        L3 l3,                                              // L3 능동 관측. 띄워 본 결과가 없으면 null
        JsonNode upgrade, List<Long> sameCveFindings,       // 같은 스캔에서 CVE가 같은 다른 Finding id
        OffsetDateTime firstSeenAt, OffsetDateTime lastSeenAt) {

    /** path는 이미지 안 위치 (예: app.jar 안의 BOOT-INF/lib/…). 모르면 null */
    public record Component(String purl, String name, String version, String ecosystem, String path) {}

    /** description은 스캐너 설명 원문. cwe·references는 없으면 빈 배열 */
    public record Vulnerability(String id, String severity, String severityNote, String title, String description,
                                String affectedFeature, List<String> fixedVersions,
                                List<String> cwe, List<String> references) {}

    /** 현재 판정. callgraph·engine은 DB의 JSONB를 그대로, evidence는 ord 순서 배열.
     * vulnFunctionIds는 판정에 쓴 취약 함수(API-10 id), 없으면 빈 배열 */
    public record Verdict(String status, String method, String summary, String notAnalyzedReason, String ruleId,
                          List<Integer> vulnFunctionIds,
                          JsonNode callgraph, JsonNode evidence, OffsetDateTime analyzedAt, JsonNode engine) {}

    /** 사람 검토. 아직 검토 전이면 reviewer는 null이다. history는 include=reviewHistory일 때만 */
    public record Review(String reviewState, String status, String note, Reviewer reviewer, OffsetDateTime reviewedAt,
                         int version, boolean disagreesWithTool, JsonNode proposal, CarriedFrom carriedFrom,
                         String resetReason, List<History> history) {}

    public record Reviewer(long id, String name) {}
    /**
     * L3 능동 관측 (FR-14): 이 이미지를 실제로 띄워 시나리오를 보냈을 때 취약 코드 쪽으로 어디까지 실행됐나.
     * 판정 옆의 근거이고 판정·검토를 바꾸지 않는다. reached·regionsChecked·startupOnly는 목록(API-04)과 같다.
     * during은 그 수준에 닿은 구간 id("startup" 또는 run.invocations의 segment), functions·regions·paths는
     * 러너 출력 그대로(실행된 취약 함수, 구간과 실행된 줄, L2 호출 경로를 진입점부터 끊기지 않고 탄 단계 수)
     */
    public record L3(String reached, boolean regionsChecked, boolean startupOnly,
                     JsonNode during, JsonNode functions, JsonNode regions, JsonNode paths, String note, L3Run run) {}
    /** 그 관측의 근거 항목 (FR-14 수용 기준 3). configKeys는 이름과 켜짐 여부뿐이고 값은 없다 */
    public record L3Run(long scanId, String scenario, String observationMethod, OffsetDateTime observedAt,
                        JsonNode build, JsonNode configKeys, JsonNode invocations) {}

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
                l3, upgrade, sameCveFindings, firstSeenAt, lastSeenAt);
    }
}