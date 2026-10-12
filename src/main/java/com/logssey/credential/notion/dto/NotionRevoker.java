package com.logssey.credential.notion.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** 토큰을 폐기한 주체. type은 bot, organization_bot, user 중 하나 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record NotionRevoker(String type, String id) {
}
