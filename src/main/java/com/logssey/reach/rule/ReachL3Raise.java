package com.logssey.reach.rule;

import java.util.List;

import org.springframework.stereotype.Component;

/**
 * L3 결과로 도구 판정을 어디까지 올리나 (FR-14). 결과를 받을 때(API-13)와 목록·상세가 같은 계산을 쓴다.
 * 한도는 CVE마다 규칙 데이터(rules.json l3)가 정한다: 구간이나 함수가 실행돼도 규칙이 본 조건(설정·기능 사용)이
 * 성립한다는 뜻이 아니면 올리지 않거나 확인 못 함까지만 올린다(예: 모든 응답 쓰기에서 실행되는 Tomcat 구간).
 * 앱과 상관없는 CVE의 성질이라 서버 한 곳에서 정하고, 저장된 L3 결과를 다시 쓰는 재대조에도 같이 적용된다
 */
@Component
public class ReachL3Raise {

    private static final List<String> RAISABLE_TO_REACHABLE = List.of("UNREACHABLE", "UNKNOWN");

    private final ReachRuleData rules;

    public ReachL3Raise(ReachRuleData rules) {
        this.rules = rules;
    }

    /** 동봉한 데이터 파일로 (Spring 없이 만드는 Service·Repository 테스트용) */
    public static ReachL3Raise bundled() {
        return new ReachL3Raise(new ReachRuleData(new ReachVulnFunctionData()));
    }

    /**
     * 이 L3 결과가 판정을 올릴 수 있는 한도: REACHABLE / UNKNOWN / NONE.
     * 구간 실행(REGION)은 CVE의 region 한도, 함수만 실행되고 구간은 확인 못 함(FUNCTION, regionsChecked=false)은 function 한도.
     * 실행 없음·확인 못 함·구간을 봤는데 실행 안 됨은 올리지 않는다(내리지도 않는다)
     */
    public String limit(String vulnerabilityId, String reached, boolean regionsChecked) {
        var limit = rules.l3Limit(vulnerabilityId);
        if ("REGION".equals(reached)) return limit.region();
        if ("FUNCTION".equals(reached) && !regionsChecked) return limit.function();
        return "NONE";
    }

    /** 올린 판정. 올리지 않으면 null (한도 REACHABLE: 도달 불가·확인 못 함 → 도달 가능, UNKNOWN: 도달 불가 → 확인 못 함) */
    public String raise(String vulnerabilityId, String status, String reached, boolean regionsChecked) {
        String limit = limit(vulnerabilityId, reached, regionsChecked);
        if ("REACHABLE".equals(limit) && RAISABLE_TO_REACHABLE.contains(status)) return "REACHABLE";
        if (!"NONE".equals(limit) && "UNREACHABLE".equals(status)) return "UNKNOWN";
        return null;
    }
}
