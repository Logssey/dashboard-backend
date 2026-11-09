package com.logssey.reach.rule.dto;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * 취약 함수 한 줄 (API-10, 명세 3-8). 수정으로 바뀐 메서드이고 호출 그래프 판정의 목표 지점이다.
 * class는 패키지까지 쓴 이름(FQN), descriptor는 JVM 메서드 시그니처. fixedVersions는 수정 버전 전부(릴리스 줄마다 하나)다.
 * fixCommits는 출처 중 GitHub 커밋을 "owner/repo@앞 8자리"로 줄인 것. confidence·note는 데이터에 있는 값을 그대로 준다
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ReachVulnFunctionResponse(
        int id,
        String cve,
        @JsonProperty("package") String packageUrl,
        @JsonProperty("class") String className,
        String method,
        String descriptor,
        List<String> fixedVersions,
        List<String> fixCommits,
        String confidence,
        String note) {
}
