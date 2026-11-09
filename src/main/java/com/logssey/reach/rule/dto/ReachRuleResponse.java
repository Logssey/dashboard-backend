package com.logssey.reach.rule.dto;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;

import tools.jackson.databind.JsonNode;

/**
 * CVE별 판정 규칙 (API-09, 명세 3-7). 데이터는 분석기의 data/rules.json이다.
 * - method: RULE(설정·타입 사실로 판정) / CALLGRAPH(호출 그래프로 판정)
 * - facts: 판정 조건에 나오는 사실. F-<rules.json의 사실 id>('!'는 뗌, 명세 0절 식별자). 호출 그래프 결과(sink 등)는 사실이 아니라 빼고 definition에만 둔다
 * - infoFacts: 판정에 쓰지 않고 참고로만 보이는 사실(rules.json의 info)
 * - defaultStatus: 어느 조건에도 맞지 않을 때의 상태(otherwise). reasons: 상태별 판정 이유(rules.json의 why_ko)
 * - vulnFunctionIds: 같은 CVE의 취약 함수(API-10 id). 같은 데이터 버전 안에서만 같다
 * - definition: include=definition일 때만. 조건식 원문(verdict)과 거기 나오는 사실의 정의(facts). 원문이라 F- 없이 rules.json 이름 그대로다
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ReachRuleResponse(
        String id,
        String cve,
        String method,
        List<String> packages,
        List<String> facts,
        List<String> infoFacts,
        List<String> evaluationOrder,
        String defaultStatus,
        Map<String, String> reasons,
        List<Integer> vulnFunctionIds,
        JsonNode definition,
        String version) {

    public ReachRuleResponse withoutDefinition() {
        return new ReachRuleResponse(id, cve, method, packages, facts, infoFacts, evaluationOrder, defaultStatus, reasons,
                vulnFunctionIds, null, version);
    }
}
