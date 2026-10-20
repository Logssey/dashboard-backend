package com.logssey.credential.validation;

/**
 * 유효성 결과 (Secret 기준 문서: source-and-validator-contract 4장, database-schema secret_validation_attempts).
 *
 * - VALID: 공급자가 이 키의 주인을 확인해 줌 (지금 이 시각, 이 방법 기준)
 * - INVALID: 공급자가 인증을 명시적으로 거절함. 만료인지 폐기인지는 따로 근거가 있어야 함
 * - UNKNOWN: 물어봤지만 결론을 못 냄 (호출 제한, 네트워크, 공급자 오류, 권한 제한 등)
 * - UNCHECKED: 묻지 않음 (지원하지 않는 형식, 원문이 없음 등)
 */
public enum ValidationResult {
    VALID,
    INVALID,
    UNKNOWN,
    UNCHECKED
}
