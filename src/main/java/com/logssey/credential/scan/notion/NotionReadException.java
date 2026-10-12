package com.logssey.credential.scan.notion;

/** Notion 읽기 실패. httpStatus가 0이면 연결 자체가 실패한 것이다 */
public class NotionReadException extends RuntimeException {

    private final int httpStatus;
    private final String code;

    public NotionReadException(int httpStatus, String code) {
        super("Notion request failed. httpStatus=" + httpStatus + ", code=" + code);
        this.httpStatus = httpStatus;
        this.code = code;
    }

    public int httpStatus() {
        return httpStatus;
    }

    public String code() {
        return code;
    }
}
