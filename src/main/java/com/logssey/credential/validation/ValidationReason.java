package com.logssey.credential.validation;

/**
 * 유효성 결과의 이유 (Secret 기준 문서: workflow-and-states "유효성 사유").
 * IDENTITY_CONFIRMED만 기준 목록에 없어 이번에 추가한 값이다 (VALID일 때 reason_code가 NOT NULL이라서).
 */
public enum ValidationReason {
    /** VALID: 공급자가 키 주인을 확인함 */
    IDENTITY_CONFIRMED,
    /** INVALID: 인증 거절. 만료·폐기 여부는 모름 */
    INVALID_UNSPECIFIED,
    /** UNCHECKED: 검증기가 지원하지 않는 형식 */
    UNSUPPORTED_TYPE,
    /** UNCHECKED: 필요한 값이 없음 */
    INCOMPLETE_CREDENTIAL,
    /** UNKNOWN: 원천에서 원문을 다시 읽지 못함 */
    SOURCE_UNAVAILABLE,
    /** UNKNOWN: 403 등 권한 제한. 무효로 단정하지 않음 */
    PERMISSION_LIMITED,
    /** UNKNOWN: 429 */
    RATE_LIMITED,
    /** UNKNOWN: 연결 실패, 시간 초과 */
    NETWORK_ERROR,
    /** UNKNOWN: 5xx, 예상하지 못한 응답 */
    PROVIDER_ERROR,
    /** UNKNOWN: 검증기 쪽 설정·인증 문제 */
    VALIDATOR_AUTH_ERROR
}
