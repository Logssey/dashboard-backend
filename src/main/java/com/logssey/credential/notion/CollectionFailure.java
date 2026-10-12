package com.logssey.credential.notion;

/**
 * 수집 실패 이유와 화면 안내 문구 (테스트 시나리오 1.4). 문구는 나중에 바꿀 수 있다.
 */
public enum CollectionFailure {

    UNAUTHORIZED("Notion 연동 토큰이 유효하지 않습니다. 다시 등록해 주세요"),
    MISSING_SCOPE("연동 토큰에 personal-access-token:read 권한이 필요합니다"),
    FORBIDDEN("이 워크스페이스에 접근할 수 없습니다. 조직 소유자에게 확인하세요"),
    RATE_LIMITED("Notion 호출 한도를 넘어 수집하지 못했습니다. 다음 수집 때 다시 시도합니다"),
    UNEXPECTED_RESPONSE("Notion 응답을 처리하지 못했습니다. 다음 수집 때 다시 시도합니다");

    private final String userMessage;

    CollectionFailure(String userMessage) {
        this.userMessage = userMessage;
    }

    public String userMessage() {
        return userMessage;
    }

    /** 429를 뺀 오류 응답을 실패 이유로 바꾼다. 401·403은 다시 시도해도 해결되지 않는다 */
    static CollectionFailure fromError(int httpStatus, String code) {
        if (httpStatus == 401) {
            return UNAUTHORIZED;
        }
        if (httpStatus == 403) {
            return "missing_scope".equals(code) ? MISSING_SCOPE : FORBIDDEN;
        }
        return UNEXPECTED_RESPONSE;
    }
}
