package com.logssey.code;

import java.time.OffsetDateTime;
import java.util.List;

public final class CodeScanDtos {

    private CodeScanDtos() {
    }

    /** 레포·도구별 마지막 검사. total 은 SARIF 의 전체 건수, high·medium·low 는 저장한 건수 */
    public record Scan(String repository, String tool, String commit, OffsetDateTime scannedAt, int total,
                       int high, int medium, int low) {
    }

    public record Finding(String repository, String tool, String commit, String ruleId, String severity, String cwe,
                          String message, String path, Integer line, String helpUri) {
    }

    public record Overview(List<Scan> scans, List<Finding> findings) {
    }

    public record Uploaded(long scanId, int total, int stored) {
    }
}
