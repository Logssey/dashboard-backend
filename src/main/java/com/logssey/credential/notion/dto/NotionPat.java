package com.logssey.credential.notion.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * PAT 한 개. 필수 칸은 id, creator, created_at, status뿐이고 나머지는 빠질 수 있다.
 * 시각 값은 에포크 밀리초 숫자다. 토큰 원문은 Notion이 주지 않는다.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record NotionPat(
        String id,
        String name,
        NotionPerson creator,
        @JsonProperty("created_at") Long createdAt,
        @JsonProperty("expires_at") Long expiresAt,
        @JsonProperty("last_used_at") Long lastUsedAt,
        String status,
        @JsonProperty("revoked_at") Long revokedAt,
        @JsonProperty("revoked_by") NotionRevoker revokedBy) {
}
