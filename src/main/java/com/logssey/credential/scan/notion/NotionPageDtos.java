package com.logssey.credential.scan.notion;

import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Notion 일반 API 응답 중 스캐너가 쓰는 칸만 (POST /v1/search, GET /v1/pages/{id}/markdown) */
final class NotionPageDtos {

    private NotionPageDtos() {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record SearchResponse(
            List<PageResult> results,
            @JsonProperty("has_more") boolean hasMore,
            @JsonProperty("next_cursor") String nextCursor) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record PageResult(String object, String id, Map<String, PageProperty> properties) {
    }

    /** 페이지 속성. 제목 속성(type = title)만 쓴다 */
    @JsonIgnoreProperties(ignoreUnknown = true)
    record PageProperty(String type, List<RichText> title) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record RichText(@JsonProperty("plain_text") String plainText) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record PageMarkdown(String id, String markdown, boolean truncated) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record ErrorBody(String code) {
    }
}
