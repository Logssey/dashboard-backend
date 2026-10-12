package com.logssey.credential.scan;

/**
 * 페이지에서 발견한 키 한 개 (credentials에 source = SCAN으로 저장).
 *
 * @param issuer          AWS / NOTION
 * @param credentialType  AWS_ACCESS_KEY / NOTION_TOKEN
 * @param externalId      AWS Access Key ID처럼 식별자가 있으면 그 값. 비밀값은 넣지 않는다
 * @param displayName     예: AWS 키 AKIA****MPLE
 * @param maskedValue     마스킹 값
 * @param fingerprint     비밀값이 보였으면 그 지문. 식별자만 보였으면 null
 * @param storageLocation 발견 위치. 예: Notion 페이지: 제목 (페이지 ID)
 */
public record LeakedCredential(
        String issuer,
        String credentialType,
        String externalId,
        String displayName,
        String maskedValue,
        String fingerprint,
        String storageLocation) {

    /** 비밀값까지 보였는지. 지문이 있으면 비밀값을 본 것이다 */
    public boolean secretExposed() {
        return fingerprint != null;
    }
}
