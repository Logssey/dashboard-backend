package com.logssey.common.error;

import org.springframework.http.HttpStatus;

/** API 명세 0.4 오류 코드 */
public enum ErrorCode {
    INVALID_INPUT(HttpStatus.BAD_REQUEST, "입력값이 올바르지 않습니다."),
    UNAUTHENTICATED(HttpStatus.UNAUTHORIZED, "로그인이 필요합니다."),
    FORBIDDEN(HttpStatus.FORBIDDEN, "요청을 처리할 수 없습니다."),
    RUNTIME_FINDING_NOT_FOUND(HttpStatus.NOT_FOUND, "런타임 Finding을 찾을 수 없습니다."),
    FINDING_VERSION_CONFLICT(HttpStatus.CONFLICT, "다른 사용자가 먼저 변경했습니다. 최신 내용을 다시 확인해 주세요."),
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
