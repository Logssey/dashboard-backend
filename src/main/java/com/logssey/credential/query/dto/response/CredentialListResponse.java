package com.logssey.credential.query.dto.response;

import java.util.List;

/** 키 목록 조회 응답 (API 명세: 키 목록 조회) */
public record CredentialListResponse(Summary summary, List<CredentialItem> items) {

    /**
     * 요약 숫자. 필터와 관계없이 전체 키 기준.
     *
     * @param totalCount     전체 키
     * @param foundCount     문서에서 발견한 키 (source = SCAN)
     * @param candidateCount 그중 구성요소가 불완전한 후보 (예: AWS Access Key ID만 보임)
     * @param inventoryCount 발급처 목록으로만 아는 키 (source = API). 위험 판정 대상이 아님
     */
    public record Summary(long totalCount, long foundCount, long candidateCount, long inventoryCount) {
    }

    /**
     * 키 한 개. 키 원문, 권한 범위, 용도는 넣지 않는다.
     * null일 수 있는 칸: displayName, externalId, expiresAt, lastUsedAt, owner, ownerTeam, location,
     * severity, missingReason
     *
     * @param source         API = 발급처 목록 수집 / SCAN = 문서에서 발견 / MANUAL
     * @param location       발견 위치 (SCAN일 때)
     * @param environment    PROD / DEV / UNKNOWN. 확인되지 않으면 UNKNOWN (PROD로 가정하지 않음)
     * @param componentState CONFIRMED = 구성요소 완전 / CANDIDATE = 불완전한 후보 / METADATA_ONLY = 목록 정보만
     * @param severity       문서에서 발견한 키는 UNASSESSED(미평가). 목록 정보만 있는 키는 null (판정 대상 아님)
     * @param missingReason  미평가 사유. CREDENTIAL_UNCONFIRMED / EXPOSURE_UNKNOWN
     */
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
            String source,
            String location,
            String environment,
            String componentState,
            String severity,
            String missingReason) {
    }
}
