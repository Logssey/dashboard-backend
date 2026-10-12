package com.logssey.credential.query.dto.response;

import java.util.List;

/** 키 목록 조회 응답 (API 명세: 키 목록 조회) */
public record CredentialListResponse(Summary summary, List<CredentialItem> items) {

    /** 요약 숫자. 필터와 관계없이 전체 키 기준 */
    public record Summary(long totalCount, long atRiskCount, long expiringSoonCount) {
    }

    /** 키 한 개. 키 원문, 권한 범위, 저장 위치, 용도는 넣지 않는다. null일 수 있는 칸: displayName, externalId, expiresAt, lastUsedAt, owner, ownerTeam */
    public record CredentialItem(
            long credentialId,
            String displayName,
            String externalId,
            String issuer,
            String credentialType,
            String status,
            String expiryPolicy,
            String expiresAt,
            String lastUsedAt,
            String owner,
            String ownerTeam,
            List<RiskRef> risks) {
    }

    /** 이 키에서 나온 탐지 */
    public record RiskRef(long eventId, String displayId, String severity, String title, String reviewStatus) {
    }
}
