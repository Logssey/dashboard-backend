package com.logssey.auth.github.dto.response;

/** 로그인 방법 조회 응답. github: GitHub 로그인을 쓸 수 있는지 */
public record AuthOptionsResponse(boolean github) {
}
