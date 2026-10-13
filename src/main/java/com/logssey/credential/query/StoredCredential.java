package com.logssey.credential.query;

import com.logssey.credential.CollectedCredential;

/**
 * DB(credentials)에 저장된 키 한 개. 키 목록 화면에 필요한 값만 담는다.
 *
 * @param credentialId    credentials.credential_id
 * @param credential      키 기본 정보 (발급자, 종류, 상태, 만료 등)
 * @param ownerTeam       담당 팀. 모르면 null
 * @param environment     키에 직접 기록된 환경(PROD/DEV). 모르면 null → 화면에는 UNKNOWN.
 *                        연결된 자산의 환경을 그대로 가져오지 않는다 (Secret 데이터베이스 스키마 문서)
 * @param source          어떻게 알게 됐나 (API = 목록 수집 / SCAN = 문서에서 발견 / MANUAL)
 * @param maskedValue     마스킹 값. 없으면 null
 * @param storageLocation 발견 위치. 없으면 null
 * @param secretSeen      지문이 있는지 = 스캔에서 비밀값까지 본 적이 있는지
 */
public record StoredCredential(
        long credentialId,
        CollectedCredential credential,
        String ownerTeam,
        String environment,
        String source,
        String maskedValue,
        String storageLocation,
        boolean secretSeen) {
}
