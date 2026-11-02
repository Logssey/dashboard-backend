package com.logssey.secretworker.notion;

/** Safe failure code and status only. Notion's error message and the page content never enter it. */
public final class NotionSourceException extends RuntimeException {
    public enum Code {
        ACCESS_DENIED, NOT_FOUND, RATE_LIMITED, UNAVAILABLE, RESPONSE_TOO_LARGE, MALFORMED_RESPONSE,
        TOKEN_UNAVAILABLE
    }

    private final Code code;
    private final int httpStatus;

    public NotionSourceException(Code code, int httpStatus) {
        super(code.name(), null, false, false);
        this.code = code;
        this.httpStatus = httpStatus;
    }

    public Code code() {
        return code;
    }

    public int httpStatus() {
        return httpStatus;
    }
}
