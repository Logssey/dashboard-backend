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
        L3 l3,
        OffsetDateTime firstSeenAt,
        ReachFindingRisk risk) {                            // 보안 점수용 이미지 등급 (ADR-D012)

    /**
     * L3 능동 관측이 닿은 곳 (FR-14). 판정(verdict)과 따로인 근거다. 이 이미지를 띄워 본 결과가 없으면 null.
     * reached: REGION(취약 구간 실행) / FUNCTION(취약 함수까지) / NONE(실행 없음) / NOT_RECORDED(확인 못 함).
     * regionsChecked는 FUNCTION일 때 구간을 봤는지(true면 봤고 미실행), startupOnly는 앱이 뜨는 동안에만 실행됐는지.
     * raiseLimit은 이 결과가 판정을 올릴 수 있는 한도(REACHABLE / UNKNOWN / NONE). 구간이 실행됐어도 그 CVE의 규칙 조건을
     * 보여 주지 않으면 UNKNOWN이나 NONE이다(규칙 데이터 l3, 서버가 판정을 올릴 때와 같은 계산)
     */
    public record L3(String reached, boolean regionsChecked, boolean startupOnly, String raiseLimit) {
    }


    public record Component(String purl, String name, String version) {
    }

    public record Vulnerability(String id, String severity, List<String> fixedVersions) {
    }

    public record Verdict(String status, String method, String summary, String notAnalyzedReason) {
    }

    public record Review(String reviewState, boolean disagreesWithTool, JsonNode proposal, String resetReason) {
    }
}