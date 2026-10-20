package com.logssey.common.error;

import org.springframework.http.HttpStatus;

/** API 명세 0.4 오류 코드 */
public enum ErrorCode {
    INVALID_INPUT(HttpStatus.BAD_REQUEST, "입력값이 올바르지 않습니다."),
    UNAUTHENTICATED(HttpStatus.UNAUTHORIZED, "로그인이 필요합니다."),
    FORBIDDEN(HttpStatus.FORBIDDEN, "요청을 처리할 수 없습니다."),
    NOT_FOUND(HttpStatus.NOT_FOUND, "요청한 대상을 찾을 수 없습니다."),
    CONFLICT(HttpStatus.CONFLICT, "진행 중인 작업과 충돌합니다."),
    PAYLOAD_TOO_LARGE(HttpStatus.CONTENT_TOO_LARGE, "요청 본문이 너무 큽니다."),
    UNPROCESSABLE(HttpStatus.UNPROCESSABLE_CONTENT, "처리할 수 없는 내용입니다."),
    EVIDENCE_REQUIRED(HttpStatus.UNPROCESSABLE_CONTENT, "판단에 필요한 근거가 부족합니다."),
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "서버 내부 오류가 발생했습니다.");

    private final HttpStatus status;
    private final String defaultMessage;

    ErrorCode(HttpStatus status, String defaultMessage) {
        this.status = status;
        this.defaultMessage = defaultMessage;
    }

    public HttpStatus status() { return status; }
    public String defaultMessage() { return defaultMessage; }
}
