package com.logssey.code;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.Date;
import java.util.function.Consumer;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.testcontainers.postgresql.PostgreSQLContainer;

import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 서비스 레포 code-scan 워크플로의 SARIF 업로드(GitHub OIDC)와 대시보드 조회. WireMock 이 GitHub 공개 키(JWKS)를 준다.
 */
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
class CodeScanIntegrationTest {

    private static final String ISSUER = "https://token.actions.githubusercontent.com";
    private static final String REPO = "Logssey/service-backend";
    private static final String WORKFLOW = REPO + "/.github/workflows/code-scan.yml@refs/heads/develop";
    private static final String WORKSPACE = "/home/runner/work/service-backend/service-backend";
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static RSAKey githubKey;
    private static RSAKey otherKey;

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
        properties.add("logssey.code.ci.jwk-set-uri", () -> github.baseUrl() + "/.well-known/jwks");
    }

    @BeforeAll
    static void keys() throws JOSEException {
        githubKey = new RSAKeyGenerator(2048).keyID("github").generate();
        otherKey = new RSAKeyGenerator(2048).keyID("github").generate();   // 같은 kid, 다른 키
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
        jdbc.execute("TRUNCATE code_findings, code_scans RESTART IDENTITY CASCADE");
        github.stubFor(WireMock.get(urlPathEqualTo("/.well-known/jwks"))
                .willReturn(okJson(new JWKSet(githubKey.toPublicJWK()).toString())));
    }

    @Test
    void theWorkflowUploadsEachToolAndANewScanReplacesTheOldOne() throws Exception {
        String token = bearer(sign(githubKey, claims()));
        mvc.perform(upload("spotbugs", "a").header(HttpHeaders.AUTHORIZATION, token))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.total").value(2))
                .andExpect(jsonPath("$.stored").value(2));
        mvc.perform(upload("semgrep", "a").header(HttpHeaders.AUTHORIZATION, token))
                .andExpect(status().isCreated());
        mvc.perform(upload("spotbugs", "b").header(HttpHeaders.AUTHORIZATION, token))
                .andExpect(status().isCreated());

        assertThat(jdbc.queryForObject("SELECT count(*) FROM code_scans", Long.class)).isEqualTo(2L);
        assertThat(jdbc.queryForObject("SELECT commit_sha FROM code_scans WHERE tool = 'spotbugs'", String.class))
                .isEqualTo("b".repeat(40));
        assertThat(jdbc.queryForObject("SELECT count(*) FROM code_findings", Long.class)).isEqualTo(4L);

        var session = login();
        mvc.perform(get("/api/v1/code/findings").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scans.length()").value(2))
                .andExpect(jsonPath("$.scans[1].tool").value("spotbugs"))
                .andExpect(jsonPath("$.scans[1].medium").value(2))
                .andExpect(jsonPath("$.findings[0].severity").value("HIGH"))
                .andExpect(jsonPath("$.findings[0].repository").value(REPO))
                .andExpect(jsonPath("$.findings[1].path").value(".github/workflows/ci.yml"));
        var report = mvc.perform(get("/api/v1/code/report").session(session))
                .andExpect(status().isOk())
                .andReturn().getResponse();
        assertThat(report.getHeader(HttpHeaders.CONTENT_DISPOSITION)).contains("logssey-code-report-");
        assertThat(report.getContentAsString(java.nio.charset.StandardCharsets.UTF_8))
                .contains("코드 취약점 리포트", "High 1건 · Medium 3건 · Low 0건", "run-shell-injection",
                        "src/main/java/com/reused/chat/ChatRepository.java:20", "검사 기준 · 정책")
                .doesNotContain("<script");
    }

    @Test
    void tokensFromAnythingButTheCodeScanWorkflowOnDevelopAreUnauthenticated() throws Exception {
        expectUnauthenticated(bearer(sign(otherKey, claims())));                                   // 서명 키가 다름
        expectUnauthenticated(token(c -> c.audience("logssey-reach")));                             // 다른 솔루션의 aud
        expectUnauthenticated(token(c -> c.claim("repository", "Logssey/other")
                .claim("job_workflow_ref", "Logssey/other/.github/workflows/code-scan.yml@refs/heads/develop")));
        expectUnauthenticated(token(c -> c.claim("event_name", "pull_request").claim("ref", "refs/pull/3/merge")));
        expectUnauthenticated(token(c -> c.claim("ref", "refs/heads/feature")));
        expectUnauthenticated(token(c -> c.claim("job_workflow_ref", REPO + "/.github/workflows/ci.yml@refs/heads/develop")));
        expectUnauthenticated(token(c -> c.claim("job_workflow_ref", REPO + "/.github/workflows/code-scan.yml@refs/heads/feature")));
        expectUnauthenticated(token(c -> c.issuer("https://example.com")));
        expectUnauthenticated(token(c -> c.expirationTime(Date.from(Instant.now().minusSeconds(120)))));
        expectUnauthenticated("Bearer not-a-jwt");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM code_scans", Long.class)).isZero();
    }

    @Test
    void theTokenOnlyUploadsAndRejectsBadInput() throws Exception {
        String token = bearer(sign(githubKey, claims()));
        mvc.perform(get("/api/v1/code/scans").header(HttpHeaders.AUTHORIZATION, token))
                .andExpect(status().isForbidden());
        mvc.perform(upload("eslint", "a").header(HttpHeaders.AUTHORIZATION, token))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/api/v1/code/scans").param("tool", "semgrep").param("commit", "abc")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"runs\":[]}")
                        .header(HttpHeaders.AUTHORIZATION, token))
                .andExpect(status().isBadRequest());
        mvc.perform(post("/api/v1/code/scans").param("tool", "semgrep").param("commit", "a".repeat(40))
                        .contentType(MediaType.APPLICATION_JSON).content("not json")
                        .header(HttpHeaders.AUTHORIZATION, token))
                .andExpect(status().isBadRequest());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM code_scans", Long.class)).isZero();
    }

    @Test
    void aSignedInUserReadsButCannotUpload() throws Exception {
        mvc.perform(get("/api/v1/code/findings")).andExpect(status().isUnauthorized());
        mvc.perform(get("/api/v1/code/report")).andExpect(status().isUnauthorized());
        var session = login();
        mvc.perform(upload("semgrep", "a").session(session).with(csrf()))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/v1/code/findings").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scans.length()").value(0));
    }

    private MockHttpServletRequestBuilder upload(String tool, String commitChar) throws IOException {
        return post("/api/v1/code/scans").param("tool", tool).param("commit", commitChar.repeat(40))
                .param("workspace", WORKSPACE)
                .contentType(MediaType.APPLICATION_JSON).content(fixture(tool.equals("eslint") ? "semgrep" : tool));
    }

    private MockHttpSession login() throws Exception {
        var login = mvc.perform(post("/api/v1/auth/login").with(csrf()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"loginId\":\"admin\",\"password\":\"admin-pass\"}"))
                .andExpect(status().isOk()).andReturn();
        return (MockHttpSession) login.getRequest().getSession(false);
    }

    private void expectUnauthenticated(String authorization) throws Exception {
        mvc.perform(upload("semgrep", "e").header(HttpHeaders.AUTHORIZATION, authorization))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }

    private String token(Consumer<JWTClaimsSet.Builder> change) throws JOSEException {
        var claims = claims();
        change.accept(claims);
        return bearer(sign(githubKey, claims));
    }

    /** service-backend code-scan.yml 이 develop push 로 받은 토큰 */
    private static JWTClaimsSet.Builder claims() {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience("logssey-code")
                .subject("repo:" + REPO + ":ref:refs/heads/develop")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .claim("repository", REPO)
                .claim("event_name", "push")
                .claim("ref", "refs/heads/develop")
                .claim("job_workflow_ref", WORKFLOW);
    }

    private static byte[] fixture(String tool) throws IOException {
        try (InputStream in = CodeScanIntegrationTest.class.getResourceAsStream("/code/" + tool + ".sarif")) {
            return in.readAllBytes();
        }
    }

    private static String sign(RSAKey key, JWTClaimsSet.Builder claims) throws JOSEException {
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims.build());
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    private static String bearer(String token) {
        return "Bearer " + token;
    }
}
