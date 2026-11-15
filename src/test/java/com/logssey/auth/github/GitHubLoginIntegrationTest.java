package com.logssey.auth.github;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;
import org.testcontainers.postgresql.PostgreSQLContainer;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;

/** GitHub 로그인 전체 흐름 (ADR-D010). WireMock 이 GitHub(토큰, 사용자 정보, 조직 멤버십)인 척한다 */
@SpringBootTest(properties = {
        "spring.config.import=",
        "logssey.admin.login-id=admin",
        "logssey.admin.password=admin-pass",
        "logssey.admin.display-name=Security Admin",
        "logssey.secret.bootstrap-security-login-id=",
        "logssey.secret.bootstrap-operations-login-id=",
        "logssey.secret.bootstrap-remediator-login-id=",
        "logssey.secret.bootstrap-remediator-team=",
        "spring.security.oauth2.client.registration.github.client-id=test-client",
        "spring.security.oauth2.client.registration.github.client-secret=test-secret",
        "spring.security.oauth2.client.registration.github.scope=read:user,read:org",
        "logssey.auth.github.allowed-organization=Logssey"
})
class GitHubLoginIntegrationTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");

    static {
        POSTGRES.start();
    }

    @RegisterExtension
    static WireMockExtension github = WireMockExtension.newInstance().options(wireMockConfig().dynamicPort()).build();

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry properties) {
        properties.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        properties.add("spring.datasource.username", POSTGRES::getUsername);
        properties.add("spring.datasource.password", POSTGRES::getPassword);
        properties.add("spring.security.oauth2.client.provider.github.token-uri",
                () -> github.baseUrl() + "/login/oauth/access_token");
        properties.add("spring.security.oauth2.client.provider.github.user-info-uri", () -> github.baseUrl() + "/user");
        properties.add("logssey.auth.github.api-base-url", github::baseUrl);
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private JdbcTemplate jdbc;

    private MockMvc mvc;

    @BeforeEach
    void reset() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        jdbc.update("DELETE FROM dashboard_users WHERE github_id IS NOT NULL OR login_id <> 'admin'");
        github.resetAll();
        github.stubFor(com.github.tomakehurst.wiremock.client.WireMock.post(urlPathEqualTo("/login/oauth/access_token"))
                .willReturn(okJson("""
                        {"access_token":"gho_test","token_type":"bearer","scope":"read:user,read:org"}
                        """)));
    }

    @Test
    void optionsTellTheLoginPageThatGitHubIsAvailable() throws Exception {
        mvc.perform(get("/api/v1/auth/options"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.github").value(true));
    }

    @Test
    void activeMemberSignsInAsAdminAndUsesExistingApis() throws Exception {
        gitHubUser(1001, "octo-dev", "Octo Dev");
        membership("active");

        MockHttpSession session = signInWithGitHub("/");

        mvc.perform(get("/api/v1/auth/me").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.displayName").value("Octo Dev"))
                .andExpect(jsonPath("$.role").value("ADMIN"));
        // 다른 모듈은 getName() = login_id 로 관리자인지 DB 에서 본다
        mvc.perform(get("/api/v1/reach/apps").session(session)).andExpect(status().isOk());

        assertThat(jdbc.queryForMap("SELECT login_id, role, password_hash FROM dashboard_users WHERE github_id = 1001"))
                .containsEntry("login_id", "octo-dev")
                .containsEntry("role", "ADMIN")
                .containsEntry("password_hash", GitHubAccountRepository.NO_PASSWORD);
        github.verify(getRequestedFor(urlPathEqualTo("/user/memberships/orgs/Logssey")));
    }

    @Test
    void nonMemberIsRefusedAndNoAccountIsCreated() throws Exception {
        gitHubUser(2002, "stranger", null);
        github.stubFor(com.github.tomakehurst.wiremock.client.WireMock.get(urlPathEqualTo("/user/memberships/orgs/Logssey"))
                .willReturn(aResponse().withStatus(404)));

        MockHttpSession session = signInWithGitHub("/login?error=github");

        mvc.perform(get("/api/v1/auth/me").session(session)).andExpect(status().isUnauthorized());
        assertThat(countGitHubAccounts()).isZero();
    }

    @Test
    void pendingInvitationIsNotEnough() throws Exception {
        gitHubUser(2003, "invited", "Invited");
        membership("pending");

        signInWithGitHub("/login?error=github");

        assertThat(countGitHubAccounts()).isZero();
    }

    @Test
    void gitHubErrorDuringMembershipCheckRefusesSignIn() throws Exception {
        gitHubUser(2004, "unlucky", "Unlucky");
        github.stubFor(com.github.tomakehurst.wiremock.client.WireMock.get(urlPathEqualTo("/user/memberships/orgs/Logssey"))
                .willReturn(aResponse().withStatus(500)));

        signInWithGitHub("/login?error=github");

        assertThat(countGitHubAccounts()).isZero();
    }

    @Test
    void gitHubUserNamedLikeThePasswordAdminCannotTakeItOver() throws Exception {
        gitHubUser(3003, "admin", "Not The Admin");
        membership("active");

        MockHttpSession session = signInWithGitHub("/login?error=github");

        mvc.perform(get("/api/v1/auth/me").session(session)).andExpect(status().isUnauthorized());
        assertThat(jdbc.queryForObject("SELECT github_id FROM dashboard_users WHERE login_id = 'admin'", Long.class))
                .isNull();
    }

    @Test
    void renamedGitHubUserKeepsTheSameAccount() throws Exception {
        long userId = jdbc.queryForObject("""
                INSERT INTO dashboard_users (login_id, password_hash, display_name, role, github_id)
                VALUES ('old-name', '!github-login', 'Octo', 'ADMIN', 1001) RETURNING user_id
                """, Long.class);
        gitHubUser(1001, "new-name", "Octo");
        membership("active");

        MockHttpSession session = signInWithGitHub("/");

        mvc.perform(get("/api/v1/auth/me").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(userId));
        assertThat(jdbc.queryForObject("SELECT login_id FROM dashboard_users WHERE user_id = ?", String.class, userId))
                .isEqualTo("new-name");
    }

    @Test
    void gitHubAccountCannotUsePasswordLogin() throws Exception {
        gitHubUser(1001, "octo-dev", "Octo Dev");
        membership("active");
        signInWithGitHub("/");

        mvc.perform(post("/api/v1/auth/login").with(csrf()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"loginId\":\"octo-dev\",\"password\":\"" + GitHubAccountRepository.NO_PASSWORD + "\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void passwordAdminStillWorksAndOtherApisStillNeedLogin() throws Exception {
        mvc.perform(get("/api/v1/reach/apps")).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/auth/login").with(csrf()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"loginId\":\"admin\",\"password\":\"admin-pass\"}"))
                .andExpect(status().isOk());
    }

    /** /oauth2/authorization/github → (GitHub 인가 화면 생략) → /login/oauth2/code/github 콜백 */
    private MockHttpSession signInWithGitHub(String expectedRedirect) throws Exception {
        MvcResult authorization = mvc.perform(get("/oauth2/authorization/github"))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        String location = authorization.getResponse().getRedirectedUrl();
        assertThat(location).startsWith("https://github.com/login/oauth/authorize");
        String state = UriUtils.decode(
                UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst("state"), StandardCharsets.UTF_8);
        MockHttpSession session = (MockHttpSession) authorization.getRequest().getSession(false);

        mvc.perform(get("/login/oauth2/code/github").param("code", "test-code").param("state", state).session(session))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(expectedRedirect));
        return session;
    }

    private void gitHubUser(long id, String login, String name) {
        String nameJson = name == null ? "null" : "\"" + name + "\"";
        github.stubFor(com.github.tomakehurst.wiremock.client.WireMock.get(urlPathEqualTo("/user"))
                .willReturn(okJson("{\"id\":" + id + ",\"login\":\"" + login + "\",\"name\":" + nameJson + "}")));
    }

    private void membership(String state) {
        github.stubFor(com.github.tomakehurst.wiremock.client.WireMock.get(urlPathEqualTo("/user/memberships/orgs/Logssey"))
                .willReturn(okJson("{\"state\":\"" + state + "\",\"role\":\"member\"}")));
    }

    private long countGitHubAccounts() {
        return jdbc.queryForObject("SELECT count(*) FROM dashboard_users WHERE github_id IS NOT NULL", Long.class);
    }
}
