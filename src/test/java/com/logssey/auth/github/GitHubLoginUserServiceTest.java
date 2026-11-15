package com.logssey.auth.github;

import static com.github.tomakehurst.wiremock.client.WireMock.anyRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;

/** 조직 설정이 비어 있으면 아무도 들어오지 못한다 (fail closed) */
class GitHubLoginUserServiceTest {

    @RegisterExtension
    static WireMockExtension github = WireMockExtension.newInstance().options(wireMockConfig().dynamicPort()).build();

    @Test
    void emptyAllowedOrganizationRefusesEveryoneWithoutAskingGitHub() {
        github.stubFor(get(urlPathEqualTo("/user")).willReturn(okJson("{\"id\":1,\"login\":\"octo\",\"name\":\"Octo\"}")));
        GitHubLoginUserService service = new GitHubLoginUserService(
                new GitHubOrgMembershipClient(github.baseUrl()), null, "  ");

        assertThatThrownBy(() -> service.loadUser(request()))
                .isInstanceOf(OAuth2AuthenticationException.class)
                .extracting(e -> ((OAuth2AuthenticationException) e).getError().getErrorCode())
                .isEqualTo(GitHubLoginUserService.NOT_ORG_MEMBER);
        github.verify(0, anyRequestedFor(urlPathMatching("/user/memberships/.*")));
    }

    private static OAuth2UserRequest request() {
        ClientRegistration registration = ClientRegistration.withRegistrationId("github")
                .clientId("test-client")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri("https://github.com/login/oauth/authorize")
                .tokenUri("https://github.com/login/oauth/access_token")
                .userInfoUri(github.baseUrl() + "/user")
                .userNameAttributeName("id")
                .build();
        OAuth2AccessToken token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "gho_test",
                Instant.now(), Instant.now().plusSeconds(60));
        return new OAuth2UserRequest(registration, token);
    }
}
