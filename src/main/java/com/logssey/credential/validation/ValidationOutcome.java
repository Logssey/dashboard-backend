package com.logssey.credential.validation;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/**
 * 검증 한 번의 결과. 키 원문은 들어 있지 않다 (Secret ADR-S005).
 * 나중에 secret_validation_attempts 한 행 + secret_evidence(IDENTITY) 한 행으로 저장할 수 있게 칸을 맞췄다.
 *
 * @param result           VALID / INVALID / UNKNOWN / UNCHECKED
 * @param reason           이유
 * @param httpStatus       공급자 응답 상태 코드. 요청을 안 했거나 응답을 못 받았으면 null
 * @param retryAfter       429일 때 공급자가 알려준 대기 시간. 없으면 null
 * @param safeFacts        저장해도 되는 사실만 (예: 주체 종류, 워크스페이스 이름). 원문·응답 본문 전체는 넣지 않음
 * @param validatorId      검증기 이름
 * @param validatorVersion 검증기 버전
 * @param endpointClass    어떤 종류의 호출로 확인했는지
 * @param checkedAt        검증 시각 (UTC)
 */
public record ValidationOutcome(
        ValidationResult result,
        ValidationReason reason,
        Integer httpStatus,
        Duration retryAfter,
        Map<String, String> safeFacts,
        String validatorId,
        String validatorVersion,
        String endpointClass,
        Instant checkedAt) {

    public ValidationOutcome {
        safeFacts = safeFacts == null ? Map.of() : Map.copyOf(safeFacts);
    }
}
