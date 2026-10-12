package com.logssey.credential.notion.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** 토큰을 만든 사람. email, profile_photo_url은 쓰지 않으므로 받지 않는다 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record NotionPerson(String id, String name) {
}
