package com.logssey.credential.notion.dto;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** Notion Admin API PAT 목록 응답 한 페이지. next_cursor는 has_more가 true일 때만 온다 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record NotionPatPage(
        List<NotionPat> results,
        @JsonProperty("has_more") boolean hasMore,
        @JsonProperty("next_cursor") String nextCursor) {
}
