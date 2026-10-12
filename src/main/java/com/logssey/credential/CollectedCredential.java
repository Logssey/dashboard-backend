package com.logssey.credential;

import java.time.Instant;

/**
 * 플랫폼에서 수집한 키 한 개의 정보. ERD 초안의 credentials 테이블과 같은 모양이다.
 * 키 원문은 담지 않는다 (ADR-D009).
 *
 * @param issuer         발급자. 예: NOTION
 * @param credentialType 키 종류. 예: NOTION_PAT
 * @param externalId     플랫폼 쪽 ID
 * @param displayName    플랫폼에서 붙인 이름. 없으면 null
 * @param owner          만든 사람 이름(없으면 ID). 모르면 null
 * @param issuedAt       발급 시각
 * @param expiryPolicy   만료 방식
 * @param expiresAt      만료 시각. expiryPolicy가 FIXED일 때만 있음
 * @param lastUsedAt     마지막 사용 시각. 모르면 null
 * @param status         상태
 * @param revokedAt      폐기 시각. 폐기된 경우만
 * @param revokedBy      폐기한 주체. 예: user:user-0009
 */
public record CollectedCredential(
        String issuer,
        String credentialType,
        String externalId,
        String displayName,
        String owner,
        Instant issuedAt,
        ExpiryPolicy expiryPolicy,
        Instant expiresAt,
        Instant lastUsedAt,
        CredentialStatus status,
        Instant revokedAt,
        String revokedBy) {
}
