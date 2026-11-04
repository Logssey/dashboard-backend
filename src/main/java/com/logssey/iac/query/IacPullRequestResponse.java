package com.logssey.iac.query;

import java.time.OffsetDateTime;
import java.util.List;

import tools.jackson.databind.JsonNode;

/**
 * S-02 PR 상세 (API 계약 GET /prs/{number}). 가장 최근 run 기준.
 * title 은 GitHub 정보라 저장하지 않는다. resources·state 는 분석이 끝난 run 만 (② 에서 막히면 null).
 * resourceFindings 는 경로 없이 리소스 하나에 걸리는 ① 발견 건 (path.imds_v1_added).
 */
public record IacPullRequestResponse(int number, String title, long runId, String headSha, String status,
                                     String verdict, String highestSeverity, OffsetDateTime checkedAt,
                                     Gate gate, List<PathChange> paths, List<ResourceFinding> resourceFindings,
                                     JsonNode resources, JsonNode state) {

    public record Gate(String status, List<GateFinding> findings) {
    }

    public record GateFinding(String ruleId, String enforcement, String severity, String address) {
    }

    public record ResourceFinding(String ruleId, String enforcement, String severity, String address, String action) {
    }

    public record PathChange(String change, int tier, String ruleId, String severity, JsonNode hops, Cause cause,
                             JsonNode evidence) {
    }

    public record Cause(String address, String action) {
    }
}
