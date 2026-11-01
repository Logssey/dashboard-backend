package com.logssey.reach.ci;

import java.time.OffsetDateTime;
import java.util.List;

import tools.jackson.databind.JsonNode;

/**
 * API-13 결과 묶음 (gzip을 푼 JSON). 값 검사와 대문자 맞추기는 ReachResultService가 한다.
 * 명세는 "결과 묶음 형식은 run-reach.sh를 러너용으로 바꿀 때 확정한다"고만 해서, 아래 모양은 구현하며 정했다:
 * verdicts의 한 항목은 Finding 하나이고 모양은 API 명세 3-3 Finding, 3-4 Verdict, 3-5 Evidence를 따른다(API-05 상세와 같은 이름).
 * sbom, matches, reachResult는 받기만 하고 아직 저장하지 않는다(보관 방식 ARD Q-06 미정).
 * failure가 있으면 러너에서 실패한 것이라 stages, tools만 보고 스캔을 FAILED로 끝낸다
 */
public record ReachResultBundle(
        JsonNode sbom,
        JsonNode matches,
        List<Item> verdicts,
        JsonNode reachResult,
        JsonNode tools,
        JsonNode analysis,
        List<JsonNode> stages,
        Failure failure) {

    /** Finding 하나. deployment가 없으면 UNKNOWN(L1 자동화 전), proposal은 새 Finding의 검토 전 제안 */
    public record Item(Component component, Vulnerability vulnerability, List<String> sources, String deployment,
                       JsonNode upgrade, Verdict verdict, Proposal proposal) {}

    /** ecosystem이 없으면 purl 타입(pkg:maven/… → maven)으로 채운다 */
    public record Component(String purl, String name, String version, String ecosystem, String path) {}

    public record Vulnerability(String id, String severity, String severityNote, String title, String description,
                                String affectedFeature, List<String> fixedVersions, List<String> cwe,
                                List<String> references) {}

    /** 도구 판정. MANUAL은 사람 판정이라 받지 않는다. evidence 항목은 3-5 모양 그대로(order는 배열 순서로 매긴다) */
    public record Verdict(String status, String method, String summary, String notAnalyzedReason, String ruleId,
                          List<Integer> vulnFunctionIds, JsonNode callgraph, List<JsonNode> evidence,
                          OffsetDateTime analyzedAt, JsonNode engine) {}

    public record Proposal(String status, String summary, String reference) {}

    /** 스캔 실패 사유 (명세 3-1 failure). code는 E-코드 */
    public record Failure(String code, String stage, String message) {}
}
