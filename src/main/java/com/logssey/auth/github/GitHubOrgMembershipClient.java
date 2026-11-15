package com.logssey.auth.github;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * 로그인한 사람이 GitHub 조직의 활성 멤버인지 본다 (ADR-D010, Grafana allowed_organizations 와 같은 기준).
 * GET /user/memberships/orgs/{org} 는 로그인한 사람 자신의 멤버십만 돌려준다. read:org 권한이 필요하다.
 */
@Component
class GitHubOrgMembershipClient {

    private final RestClient restClient;

    GitHubOrgMembershipClient(@Value("${logssey.auth.github.api-base-url:https://api.github.com}") String apiBaseUrl) {
        this.restClient = RestClient.builder()
                .baseUrl(apiBaseUrl)
                .defaultHeader("Accept", "application/vnd.github+json")
                .defaultHeader("X-GitHub-Api-Version", "2022-11-28")
                .build();
    }

    /** 활성 멤버면 true. 멤버가 아니거나 초대 대기 중이면 false. GitHub 오류는 예외로 올려 로그인을 막는다 */
    boolean isActiveMember(String accessToken, String organization) {
        return restClient.get()
                .uri("/user/memberships/orgs/{org}", organization)
                .headers(headers -> headers.setBearerAuth(accessToken))
                .accept(MediaType.APPLICATION_JSON)
                .exchange((request, response) -> {
                    HttpStatusCode status = response.getStatusCode();
                    if (status.isSameCodeAs(HttpStatus.NOT_FOUND) || status.isSameCodeAs(HttpStatus.FORBIDDEN)) {
                        return false;
                    }
                    if (!status.is2xxSuccessful()) {
                        throw new IllegalStateException("GitHub membership check failed: " + status.value());
                    }
                    Map<?, ?> body = response.bodyTo(Map.class);
                    return body != null && "active".equals(body.get("state"));
                });
    }
}
