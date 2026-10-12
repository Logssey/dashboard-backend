package com.logssey.credential.notion;

import java.time.Duration;
import java.util.Objects;

/**
 * Notion Admin API 연동 설정 (ADR-D010).
 *
 * @param baseUrl            실제는 https://api.notion.com/admin, 테스트는 Mock 서버 주소
 * @param token              organization bot token. 로그와 toString에 남기지 않는다
 * @param pageSize           한 번에 받을 개수. 최대 100
 * @param maxRetries         429일 때 다시 시도할 최대 횟수 (첫 요청 제외)
 * @param retryAfterFallback 429 응답에 retry-after 헤더가 없을 때 기다릴 시간.
 *                           이번 단계 기준은 DEFAULT_RETRY_AFTER_FALLBACK(1초)이다 (테스트 시나리오 1.3)
 */
public record NotionAdminSettings(
        String baseUrl,
        String token,
        int pageSize,
        int maxRetries,
        Duration retryAfterFallback) {

    public static final String REAL_BASE_URL = "https://api.notion.com/admin";
    public static final String NOTION_VERSION = "2026-06-01";
    public static final int MAX_PAGE_SIZE = 100;
    public static final int DEFAULT_MAX_RETRIES = 3;
    public static final Duration DEFAULT_RETRY_AFTER_FALLBACK = Duration.ofSeconds(1);

    /** 이번 단계 기준값(한 번에 100개, 다시 시도 3번, 대기 기본 1초)으로 만든다 */
    public static NotionAdminSettings withDefaults(String baseUrl, String token) {
        return new NotionAdminSettings(baseUrl, token, MAX_PAGE_SIZE, DEFAULT_MAX_RETRIES, DEFAULT_RETRY_AFTER_FALLBACK);
    }

    public NotionAdminSettings {
        requireText(baseUrl, "baseUrl");
        requireText(token, "token");
        if (pageSize < 1 || pageSize > MAX_PAGE_SIZE) {
            throw new IllegalArgumentException("pageSize must be between 1 and " + MAX_PAGE_SIZE);
        }
        if (maxRetries < 0) {
            throw new IllegalArgumentException("maxRetries must not be negative");
        }
        Objects.requireNonNull(retryAfterFallback, "retryAfterFallback");
    }

    private static void requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
    }

    /** 토큰이 로그에 찍히지 않게 가린다 (ADR-D009) */
    @Override
    public String toString() {
        return "NotionAdminSettings[baseUrl=" + baseUrl
                + ", token=****"
                + ", pageSize=" + pageSize
                + ", maxRetries=" + maxRetries
                + ", retryAfterFallback=" + retryAfterFallback + "]";
    }
}
