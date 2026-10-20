package com.logssey.credential.validation.notion;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/** GET /v1/users/me 응답 중 검증에 쓰는 칸만. 나머지(이메일, 아바타 등)는 읽지 않는다 */
@JsonIgnoreProperties(ignoreUnknown = true)
record NotionSelfResponse(String object, String id, String type, Bot bot) {

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Bot(Owner owner, @JsonProperty("workspace_name") String workspaceName) {
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    record Owner(String type) {
    }
}
