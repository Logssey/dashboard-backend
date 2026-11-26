package com.logssey.reach.ci;

import java.math.BigDecimal;
import java.time.OffsetDateTime;
import java.util.List;

import tools.jackson.databind.JsonNode;

/**
 * API-13 결과 묶음 (gzip을 푼 JSON). 값 검사와 대문자 맞추기는 ReachResultService가 한다.
 * 명세는 "결과 묶음 형식은 run-reach.sh를 러너용으로 바꿀 때 확정한다"고만 해서, 아래 모양은 구현하며 정했다:
 * verdicts의 한 항목은 Finding 하나이고 모양은 API 명세 3-3 Finding, 3-4 Verdict, 3-5 Evidence를 따른다(API-05 상세와 같은 이름).
 * sbom은 스캔마다 보관한다(V53 reach_sboms, 재대조 입력). matches, reachResult는 받기만 하고 저장하지 않는다.
 * failure가 있으면 러너에서 실패한 것이라 stages, tools만 보고 스캔을 FAILED로 끝낸다.
 * l3은 L3 능동 관측 결과(러너 verdict/l3.py 출력 + run, 또는 {"error": …})다. 없을 수 있고, 잘못돼도 스캔은 실패하지 않는다.
 * l3Record는 그 관측의 실행 기록({format: "TAR_XZ", content: base64})이다. 재대조가 다시 대조할 수 있게 보관한다(V57)
 */
public record ReachResultBundle(
        JsonNode sbom,
        JsonNode matches,
        List<Item> verdicts,
        JsonNode reachResult,
        JsonNode tools,
        JsonNode analysis,
        List<JsonNode> stages,
        Failure failure,
        JsonNode l3,
        JsonNode l3Record) {

    /**
     * Finding 하나. deployment는 새 Finding을 만들 때만 쓰고 없으면 UNKNOWN이다. 이미지 대상은 업로드 끝에서 L1 조회로 다시 계산한다.
     * proposal은 새 Finding의 검토 전 제안
     */
    public record Item(Component component, Vulnerability vulnerability, List<String> sources, String deployment,
                       JsonNode upgrade, Verdict verdict, Proposal proposal) {}

    /** ecosystem이 없으면 purl 타입(pkg:maven/… → maven)으로 채운다 */
    public record Component(String purl, String name, String version, String ecosystem, String path) {}

    /** cvss는 없을 수 있다(이 칸이 생기기 전의 분석기, CVSS가 없는 취약점) */
    public record Vulnerability(String id, String severity, String severityNote, String title, String description,
                                String affectedFeature, List<String> fixedVersions, List<String> cwe,
                                List<String> references, Cvss cvss) {}

    /** CVSS v3 기본 점수(0~10)와 출처(nvd, ghsa 등). 스캐너 심각도를 정한 출처의 값이다 */
    public record Cvss(BigDecimal score, String source) {}

    /** 도구 판정. MANUAL은 사람 판정이라 받지 않는다. evidence 항목은 3-5 모양 그대로(order는 배열 순서로 매긴다) */
    public record Verdict(String status, String method, String summary, String notAnalyzedReason, String ruleId,
                          List<Integer> vulnFunctionIds, JsonNode callgraph, List<JsonNode> evidence,
                          OffsetDateTime analyzedAt, JsonNode engine) {}

    public record Proposal(String status, String summary, String reference) {}

    /** 스캔 실패 사유 (명세 3-1 failure). code는 E-코드 */
    public record Failure(String code, String stage, String message) {}
}
