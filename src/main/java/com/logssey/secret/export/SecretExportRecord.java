package com.logssey.secret.export;

import java.time.OffsetDateTime;

/**
 * 내보내기 한 줄(열람 가능한 위치 하나).
 * 키 원문, HMAC 지문, 원본 경로 참조, 노션·Slack 본문을 담을 칸이 처음부터 없다.
 * 새 칸을 추가할 때는 화면(위치 API)에 이미 보이는 값인지 먼저 확인한다.
 */
public record SecretExportRecord(
        long credentialSetId,
        long occurrenceId,
        String maskedLabel,
        String issuer,
        String credentialType,
        String ruleId,
        String severity,
        String validationStatus,
        String source,
        String environment,
        String origin,
        Location location,
        String exposure,
        String exposureRange,
        String presence,
        String actionStatus,
        OffsetDateTime firstSeenAt,
        OffsetDateTime lastSeenAt,
        OffsetDateTime detectedAt) {

    /**
     * 화면에 보이는 안전한 위치 좌표.
     * kind: GITHUB_FILE, NOTION_PAGE, AWS_RESOURCE, UNAVAILABLE
     */
    public record Location(String kind, String label, String repository, String branch, String path,
                           Integer startLine, Integer endLine, String pageId, String blockId,
                           String region, String resource) {

        public boolean isFile() { return "GITHUB_FILE".equals(kind); }

        /** 파일이 아닌 위치를 도구 간에 식별하기 위한 논리 경로. */
        public String logicalName(long occurrenceId) {
            return switch (kind) {
                case "GITHUB_FILE" -> repository + "/" + path;
                case "NOTION_PAGE" -> "notion/pages/" + pageId + (blockId == null ? "/title" : "/blocks/" + blockId);
                case "AWS_RESOURCE" -> "aws/" + region + "/" + resource;
                default -> "logssey/locations/" + occurrenceId;
            };
        }
    }
}
