package com.logssey.auth.github;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.logssey.auth.github.GitHubAccountRepository.Account;

/**
 * GitHub 로그인 사용자 처리 (ADR-D010).
 *
 * 1. GitHub 사용자 정보(id, login, name)를 읽는다
 * 2. 설치 설정의 조직(logssey.auth.github.allowed-organization) 활성 멤버만 통과시킨다. 설정이 비어 있으면 모두 거부한다
 * 3. dashboard_users 계정과 잇는다 (GitHubAccountService)
 * 4. 이름(getName)이 dashboard_users.login_id 인 사용자를 돌려준다
 */
@Service
class GitHubLoginUserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    static final String NOT_ORG_MEMBER = "not_org_member";
    static final String GITHUB_UNAVAILABLE = "github_unavailable";

    private static final Logger log = LoggerFactory.getLogger(GitHubLoginUserService.class);
    private static final String NAME_ATTRIBUTE = "login";

    private final OAuth2UserService<OAuth2UserRequest, OAuth2User> userInfo = new DefaultOAuth2UserService();
    private final GitHubOrgMembershipClient membershipClient;
    private final GitHubAccountService accountService;
    private final String allowedOrganization;

    GitHubLoginUserService(GitHubOrgMembershipClient membershipClient,
                           GitHubAccountService accountService,
                           @Value("${logssey.auth.github.allowed-organization:}") String allowedOrganization) {
        this.membershipClient = membershipClient;
        this.accountService = accountService;
        this.allowedOrganization = allowedOrganization == null ? "" : allowedOrganization.strip();
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest request) {
        OAuth2User gitHubUser = userInfo.loadUser(request);
        Object id = gitHubUser.getAttribute("id");
        String login = gitHubUser.getAttribute("login");
        if (!(id instanceof Number githubId) || login == null || login.isBlank()) {
            throw failure(GITHUB_UNAVAILABLE, "GitHub user has no id or login");
        }

        if (allowedOrganization.isEmpty()) {
            log.warn("GitHub sign-in refused: logssey.auth.github.allowed-organization is empty. login={}", login);
            throw failure(NOT_ORG_MEMBER, "No GitHub organization is allowed");
        }
        if (!isActiveMember(request.getAccessToken().getTokenValue(), login)) {
            log.info("GitHub sign-in refused: not an active member of the organization. login={}", login);
            throw failure(NOT_ORG_MEMBER, "Not an active member of the allowed GitHub organization");
        }

        Account account = accountService.signIn(githubId.longValue(), login, gitHubUser.getAttribute("name"));

        Map<String, Object> attributes = new HashMap<>(gitHubUser.getAttributes());
        attributes.put(NAME_ATTRIBUTE, account.loginId());
        return new DefaultOAuth2User(List.of(new SimpleGrantedAuthority("ROLE_" + account.role())),
                attributes, NAME_ATTRIBUTE);
    }

    private boolean isActiveMember(String accessToken, String login) {
        try {
            return membershipClient.isActiveMember(accessToken, allowedOrganization);
        } catch (RuntimeException e) {
            log.warn("GitHub membership check failed. login={} reason={}", login, e.getMessage());
            throw failure(GITHUB_UNAVAILABLE, "GitHub membership check failed");
        }
    }

    private static OAuth2AuthenticationException failure(String code, String message) {
        return new OAuth2AuthenticationException(new OAuth2Error(code), message);
    }
}
