package com.logssey.secret.export;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

/** 내보내기 형식. 파일 이름에는 형식과 날짜만 넣고 사용자·대상 정보는 넣지 않는다. */
public enum SecretExportFormat {
    SARIF("sarif", "application/sarif+json", "sarif"),
    LOGSSEY_JSON("logssey-json", "application/json", "json"),
    GITLEAKS("gitleaks", "application/json", "json");

    private final String code;
    private final String contentType;
    private final String extension;

    SecretExportFormat(String code, String contentType, String extension) {
        this.code = code;
        this.contentType = contentType;
        this.extension = extension;
    }

    public String code() { return code; }
    public String contentType() { return contentType; }

    public String filename(java.time.LocalDate date) {
        return "logssey-secrets-" + code + "-" + date + "." + extension;
    }

    public static SecretExportFormat parse(String value) {
        for (var format : values()) if (format.code.equals(value)) return format;
        throw new ApiException(ErrorCode.INVALID_INPUT);
    }
}
