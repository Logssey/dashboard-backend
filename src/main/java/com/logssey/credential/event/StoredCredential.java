package com.logssey.credential.event;

import com.logssey.credential.CollectedCredential;

/**
 * DB(credentials)에 저장된 키 한 개와, 탐지 이벤트를 만들 때 필요한 정보.
 *
 * @param credentialId     credentials.credential_id
 * @param credential       위험 판단에 넣을 키 정보
 * @param ownerTeam        담당 팀. 모르면 null
 * @param environment      키의 환경(PROD/DEV). 모르면 null
 * @param assetId          연결된 자산. 없으면 null
 * @param assetEnvironment 연결된 자산의 환경. 자산이 없으면 null
 * @param source           어떻게 알게 됐나 (API / SCAN / MANUAL)
 * @param maskedValue      마스킹 값. 없으면 null
 * @param storageLocation  저장·발견 위치. 없으면 null
 * @param secretExposed    지문이 있는지 = 스캔에서 비밀값 원문을 본 적이 있는지
 */
public record StoredCredential(
        long credentialId,
        CollectedCredential credential,
        String ownerTeam,
        String environment,
        Long assetId,
        String assetEnvironment,
        String source,
        String maskedValue,
        String storageLocation,
        boolean secretExposed) {

    /** 플랫폼 API로 수집한 키 (유출 정보 없음) */
    public StoredCredential(long credentialId, CollectedCredential credential, String ownerTeam,
                            String environment, Long assetId, String assetEnvironment) {
        this(credentialId, credential, ownerTeam, environment, assetId, assetEnvironment, "API", null, null, false);
    }
}
