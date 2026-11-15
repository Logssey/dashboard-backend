package com.logssey.auth.github;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.testcontainers.postgresql.PostgreSQLContainer;

/** GitHub 등록 설정이 없으면(로컬·기존 테스트) GitHub 경로가 열리지 않고 비밀번호 로그인만 된다 */
@SpringBootTest(properties = {
        "spring.config.import=",
        "logssey.admin.login-id=admin",
        "logssey.admin.password=admin-pass",
        "logssey.admin.display-name=Security Admin",
        "logssey.secret.bootstrap-security-login-id=",
        "logssey.secret.bootstrap-operations-login-id=",
        "logssey.secret.bootstrap-remediator-login-id=",
        "logssey.secret.bootstrap-remediator-team="
})
class GitHubLoginDisabledIntegrationTest {

    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");

    static {
        POSTGRES.start();
    }

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry properties) {
        properties.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        properties.add("spring.datasource.username", POSTGRES::getUsername);
        properties.add("spring.datasource.password", POSTGRES::getPassword);
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @Autowired
    private WebApplicationContext context;

    @Test
    void optionsSayNoGitHubAndGitHubPathsStayClosed() throws Exception {
        MockMvc mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();

        mvc.perform(get("/api/v1/auth/options"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.github").value(false));
        mvc.perform(get("/oauth2/authorization/github")).andExpect(status().isUnauthorized());
        mvc.perform(get("/login/oauth2/code/github")).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/auth/login").with(csrf()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"loginId\":\"admin\",\"password\":\"admin-pass\"}"))
                .andExpect(status().isOk());
    }
}
