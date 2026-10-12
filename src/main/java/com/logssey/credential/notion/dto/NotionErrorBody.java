package com.logssey.credential.notion.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** 오류 응답. 판단은 code로만 하고 message는 화면에 보여주지 않는다 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record NotionErrorBody(String code, String message) {
}
