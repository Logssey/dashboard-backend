package com.logssey.iac.auth;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 호스트 수집기 토큰 (IaC 보안 ADR-13). 맞는 토큰만 수집 결과를 SYSTEM 으로 기록하고,
 * 토큰 헤더가 없는 요청은 기존 관리자 세션 체인이 그대로 받는다.
 */
@SpringBootTest(properties = {
        "spring.config.import=",
        "logssey.admin.login-id=admin",
        "logssey.admin.password=admin-pass",
        "logssey.admin.display-name=Security Admin",
        "logssey.secret.bootstrap-security-login-id=",
        "logssey.secret.bootstrap-operations-login-id=",
        "logssey.secret.bootstrap-remediator-login-id=",
        "logssey.secret.bootstrap-remediator-team=",
        "logssey.iac.collector-token=" + IacCollectorSecurityIntegrationTest.TOKEN
})
class IacCollectorSecurityIntegrationTest {

    static final String TOKEN = "collector-token-for-tests-0123456789abcdef";
    private static final String PATH = "/api/v1/iac/jobs/collect-graph/runs";
    private static final String BODY = """
            {"status":"SUCCEEDED","startedAt":"2026-11-18T03:00:00+09:00",
             "finishedAt":"2026-11-18T03:12:00+09:00","stats":{"nodes":120}}
            """;
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");

    static {
        POSTGRES.start();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry properties) {
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

    @Autowired
    private JdbcTemplate jdbc;

    private MockMvc mvc;

    @BeforeEach
    void reset() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
        jdbc.execute("TRUNCATE iac_jobs, iac_audit_events RESTART IDENTITY CASCADE");
    }

    @Test
    void collectorTokenRecordsTheRunAsSystem() throws Exception {
        mvc.perform(post(PATH).header(IacCollectorSecurityConfig.HEADER, TOKEN)
                        .contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.enrichJobId").isNumber());
        assertThat(jdbc.queryForList("SELECT DISTINCT actor_kind FROM iac_audit_events", String.class))
                .containsExactly("SYSTEM");
    }

    @Test
    void wrongTokensAreUnauthenticatedAndRecordNothing() throws Exception {
        for (String token : new String[] {"", "wrong", TOKEN + "x", TOKEN.substring(1)}) {
            mvc.perform(post(PATH).header(IacCollectorSecurityConfig.HEADER, token)
                            .contentType(MediaType.APPLICATION_JSON).content(BODY))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
        }
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_jobs", Long.class)).isZero();
    }

    @Test
    void theTokenOpensOnlyTheCollectionEndpoint() throws Exception {
        mvc.perform(post("/api/v1/iac/jobs/enrich-graph/trigger").header(IacCollectorSecurityConfig.HEADER, TOKEN))
                .andExpect(status().is4xxClientError());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_jobs", Long.class)).isZero();
    }

    @Test
    void withoutTheHeaderTheSessionChainStillApplies() throws Exception {
        mvc.perform(post(PATH).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isUnauthorized());
        var login = mvc.perform(post("/api/v1/auth/login").with(csrf()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"loginId\":\"admin\",\"password\":\"admin-pass\"}"))
                .andExpect(status().isOk()).andReturn();
        mvc.perform(post(PATH).session((MockHttpSession) login.getRequest().getSession(false))
                        .with(csrf()).contentType(MediaType.APPLICATION_JSON).content(BODY))
                .andExpect(status().isCreated());
        assertThat(jdbc.queryForList("SELECT DISTINCT actor_kind FROM iac_audit_events", String.class))
                .containsExactly("USER");
    }
}
