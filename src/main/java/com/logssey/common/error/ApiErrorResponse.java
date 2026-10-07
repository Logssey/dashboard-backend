package com.logssey.common.error;

/** 오류 응답 본문: { "code": "...", "message": "..." } (API 명세 0.4) */
public record ApiErrorResponse(String code, String message) {

    public static ApiErrorResponse of(ErrorCode errorCode) {
        return new ApiErrorResponse(errorCode.name(), errorCode.defaultMessage());
    }

    public static ApiErrorResponse of(ErrorCode errorCode, String message) {
        return new ApiErrorResponse(errorCode.name(), message);
    }

    /** 보안 필터처럼 스프링 MVC 밖에서 직접 쓸 때 사용. 메시지는 우리가 정한 고정 문구라 따옴표·역슬래시만 처리한다 */
    public String toJson() {
        return "{\"code\":\"" + escape(code) + "\",\"message\":\"" + escape(message) + "\"}";
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
