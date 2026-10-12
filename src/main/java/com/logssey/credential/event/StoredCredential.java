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
 */
public record StoredCredential(
        long credentialId,
        CollectedCredential credential,
        String ownerTeam,
        String environment,
        Long assetId,
        String assetEnvironment) {
}
