package com.logssey.credential.scan.notion;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import com.logssey.credential.notion.Sleeper;
import com.logssey.credential.scan.notion.NotionPageDtos.ErrorBody;
import com.logssey.credential.scan.notion.NotionPageDtos.PageMarkdown;
import com.logssey.credential.scan.notion.NotionPageDtos.PageProperty;
import com.logssey.credential.scan.notion.NotionPageDtos.PageResult;
import com.logssey.credential.scan.notion.NotionPageDtos.RichText;
import com.logssey.credential.scan.notion.NotionPageDtos.SearchResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClient.RequestHeadersSpec.ConvertibleClientHttpResponse;

/**
 * 읽기 전용 Notion 수집기(logssey-secret-collector-dev)로 페이지를 읽는다.
 *
 * - 페이지 목록: POST /v1/search (filter object = page). 수집기에 공유된 페이지만 나온다
 * - 페이지 내용: GET /v1/pages/{id}/markdown
 * - 429는 retry-after만큼 기다렸다가 최대 3번 다시 시도한다 (Admin API 수집기와 같은 기준)
 * - 토큰, 페이지 내용은 로그에 남기지 않는다
 */
public class NotionPageReader {

    public static final String REAL_BASE_URL = "https://api.notion.com";
    public static final String NOTION_VERSION = "2026-03-11";
    static final int PAGE_SIZE = 100;
    static final int MAX_RETRIES = 3;
    static final Duration RETRY_AFTER_FALLBACK = Duration.ofSeconds(1);

    private final RestClient restClient;
    private final Sleeper sleeper;

    public NotionPageReader(String baseUrl, String token, Sleeper sleeper) {
        Objects.requireNonNull(token, "token");
        this.sleeper = Objects.requireNonNull(sleeper, "sleeper");
        // HTTP/1.1로 고정한다. 기본값(HTTP/2)은 http:// 주소에 본문이 있는 POST를 보낼 때 업그레이드를 시도하는데,
        // 일부 서버(테스트용 WireMock 등)가 이를 받지 못해 연결이 끊긴다. https인 실제 Notion에서도 HTTP/1.1로 동작한다
        HttpClient httpClient = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build();
        this.restClient = RestClient.builder()
                .requestFactory(new JdkClientHttpRequestFactory(httpClient))
                .baseUrl(baseUrl)
                .defaultHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .defaultHeader("Notion-Version", NOTION_VERSION)
                .build();
    }

    public List<NotionPage> listSharedPages() {
        List<NotionPage> pages = new ArrayList<>();
        String cursor = null;
        do {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("filter", Map.of("property", "object", "value", "page"));
            body.put("page_size", PAGE_SIZE);
            if (cursor != null) {
                body.put("start_cursor", cursor);
            }
            SearchResponse response = withRetry(() -> restClient.post()
                    .uri("/v1/search")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(body)
                    .exchange((request, res) -> read(res, SearchResponse.class)));
            if (response.results() != null) {
                for (PageResult result : response.results()) {
                    if ("page".equals(result.object()) && result.id() != null) {
                        pages.add(new NotionPage(result.id(), title(result)));
                    }
                }
            }
            cursor = response.hasMore() ? response.nextCursor() : null;
        } while (cursor != null && !cursor.isBlank());
        return pages;
    }

    public String readMarkdown(String pageId) {
        PageMarkdown page = withRetry(() -> restClient.get()
                .uri("/v1/pages/{pageId}/markdown", pageId)
                .exchange((request, res) -> read(res, PageMarkdown.class)));
        return page.markdown() != null ? page.markdown() : "";
    }

    private <T> T withRetry(java.util.function.Supplier<T> call) {
        int retries = 0;
        while (true) {
            try {
                return call.get();
            } catch (RateLimited e) {
                if (retries >= MAX_RETRIES) {
                    throw new NotionReadException(429, "rate_limited");
                }
                retries++;
                sleeper.sleep(e.wait);
            }
        }
    }

    private static <T> T read(ConvertibleClientHttpResponse response, Class<T> type) throws java.io.IOException {
        int status = response.getStatusCode().value();
        if (status == 200) {
            T body = response.bodyTo(type);
            if (body == null) {
                throw new NotionReadException(200, "empty_body");
            }
            return body;
        }
        if (status == 429) {
            throw new RateLimited(retryAfter(response.getHeaders().getFirst("Retry-After")));
        }
        String code = null;
        try {
            ErrorBody error = response.bodyTo(ErrorBody.class);
            code = error != null ? error.code() : null;
        } catch (RuntimeException ignored) {
            // 본문이 없으면 상태 코드로만 판단한다
        }
        throw new NotionReadException(status, code);
    }

    private static Duration retryAfter(String headerValue) {
        if (headerValue != null) {
            try {
                long seconds = Long.parseLong(headerValue.trim());
                if (seconds >= 0) {
                    return Duration.ofSeconds(seconds);
                }
            } catch (NumberFormatException ignored) {
                // 기본값을 쓴다
            }
        }
        return RETRY_AFTER_FALLBACK;
    }

    private static String title(PageResult result) {
        if (result.properties() != null) {
            for (PageProperty property : result.properties().values()) {
                if (property != null && "title".equals(property.type()) && property.title() != null) {
                    String text = property.title().stream()
                            .map(RichText::plainText)
                            .filter(Objects::nonNull)
                            .collect(Collectors.joining());
                    if (!text.isBlank()) {
                        return text;
                    }
                }
            }
        }
        return "제목 없음";
    }

    /** 429 신호. 재시도 루프 안에서만 쓴다 */
    private static final class RateLimited extends RuntimeException {

        private final Duration wait;

        RateLimited(Duration wait) {
            super(null, null, false, false);
            this.wait = wait;
        }
    }

    @Override
    public String toString() {
        return "NotionPageReader[token=****]";
    }
}
