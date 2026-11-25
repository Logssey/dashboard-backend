package com.logssey.iac.auth;

import java.time.Instant;
import java.util.Date;
import java.util.function.Consumer;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.logssey.iac.run.IacPlanFixtures;
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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * infrastructure iac-report 워크플로의 GitHub OIDC 인증 (IaC 보안 ADR-13). WireMock 이 GitHub 공개 키(JWKS)를 주고,
 * 테스트가 만든 키로 서명한 토큰을 보낸다. 토큰 없는 요청은 기존 관리자 세션 체인이 그대로 받아야 한다.
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
class IacCiOidcIntegrationTest {

    private static final String ISSUER = "https://token.actions.githubusercontent.com";
    private static final String REPO = "Logssey/infrastructure";
    /** 실제 토큰의 sub (2026-07-15 뒤에 만든 레포라 조직·레포 ID 가 붙는다) */
    private static final String SUBJECT = "repo:Logssey@329835088/infrastructure@1372604168:environment:iac-app";
    private static final String DRIFT_SUBJECT = "repo:Logssey@329835088/infrastructure@1372604168:environment:iac-drift";
    private static final String PUSH_BODY = """
            {"repo":"%s","headSha":"%s","trigger":"PUSH","gate":{"status":"PASSED","findings":[]}}
            """;
    private static final String RUN_BODY = """
            {"repo":"%s","prNumber":58,"headSha":"%s","gate":{"status":"PASSED","findings":[]}}
            """;
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
        properties.add("logssey.iac.ci.jwk-set-uri", () -> github.baseUrl() + "/.well-known/jwks");
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
        jdbc.execute("TRUNCATE iac_run_path_changes, iac_findings, iac_plan_payloads, iac_jobs, iac_runs, iac_audit_events, "
                + "iac_repos RESTART IDENTITY CASCADE");
        jdbc.update("INSERT INTO iac_repos (full_name, default_branch, environment) VALUES (?, 'main', 'PROD')", REPO);
        jdbc.update("INSERT INTO iac_repos (full_name, default_branch, environment) VALUES ('Logssey/other', 'main', 'DEV')");
        github.stubFor(WireMock.get(urlPathEqualTo("/.well-known/jwks"))
                .willReturn(okJson(new JWKSet(githubKey.toPublicJWK()).toString())));
    }

    @Test
    void reportWorkflowRegistersARunUploadsThePlanAndReadsTheStatusAsCi() throws Exception {
        String token = bearer(sign(githubKey, claims()));
        var created = mvc.perform(post("/api/v1/iac/runs").header(HttpHeaders.AUTHORIZATION, token)
                        .contentType(MediaType.APPLICATION_JSON).content(RUN_BODY.formatted(REPO, "a".repeat(40))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("PLANNING"))
                .andReturn();
        long runId = Long.parseLong(created.getResponse().getHeader(HttpHeaders.LOCATION).replaceAll(".*/", ""));

        mvc.perform(put("/api/v1/iac/runs/" + runId + "/plan").header(HttpHeaders.AUTHORIZATION, token)
                        .contentType("application/gzip").content(IacPlanFixtures.gzipResource("plan-scrubbed.json")))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.status").value("ANALYZING"));
        mvc.perform(get("/api/v1/iac/runs/" + runId)
                        .header(HttpHeaders.AUTHORIZATION, token))
                .andExpect(status().isOk());
        mvc.perform(get("/api/v1/iac/runs/" + runId + "/result").header(HttpHeaders.AUTHORIZATION, token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.number").value(58))
                .andExpect(jsonPath("$.runId").value(runId))
                .andExpect(jsonPath("$.status").value("ANALYZING"))
                .andExpect(jsonPath("$.gate.status").value("PASS"));

        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_runs WHERE requested_by_user_id IS NULL", Long.class))
                .isEqualTo(1L);
        assertThat(jdbc.queryForList("SELECT DISTINCT actor_kind FROM iac_audit_events", String.class))
                .containsExactly("CI");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_jobs WHERE kind = 'ANALYZE_RUN'", Long.class))
                .isEqualTo(1L);
    }

    @Test
    void aTitleLongerThan256CharactersIsRejected() throws Exception {
        String body = """
                {"repo":"%s","prNumber":58,"headSha":"%s","prTitle":"%s","gate":{"status":"PASSED","findings":[]}}
                """.formatted(REPO, "9".repeat(40), "x".repeat(257));
        mvc.perform(post("/api/v1/iac/runs").header(HttpHeaders.AUTHORIZATION, bearer(sign(githubKey, claims())))
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_runs", Long.class)).isZero();
    }

    @Test
    void tokensFromAnythingButTheReportWorkflowAreUnauthenticated() throws Exception {
        expectUnauthenticated(bearer(sign(otherKey, claims())));                                 // 서명 키가 다름
        expectUnauthenticated(token(c -> c.audience("logssey-reach")));                           // 다른 솔루션의 aud
        expectUnauthenticated(token(c -> c.subject("repo:Logssey/infrastructure:pull_request"))); // PR 코드(iac-gate)
        expectUnauthenticated(token(c -> c.subject("repo:Logssey/infrastructure:ref:refs/heads/main")));
        // 이름 형식 sub: 이 레포의 실제 토큰은 ID 형식이라 이름 형식은 받지 않는다
        expectUnauthenticated(token(c -> c.subject("repo:Logssey/infrastructure:environment:iac-app")));
        expectUnauthenticated(token(c -> c.subject(SUBJECT.replace("1372604168", "1"))));      // 다른 레포 ID
        expectUnauthenticated(token(c -> c.issuer("https://example.com")));
        expectUnauthenticated(token(c -> c.expirationTime(Date.from(Instant.now().minusSeconds(120)))));
        expectUnauthenticated(token(c -> c.claim("repository", null)));
        expectUnauthenticated("Bearer not-a-jwt");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_runs", Long.class)).isZero();
    }

    @Test
    void theTokenOnlyActsForItsOwnRepositoryAndOnlyOnRuns() throws Exception {
        String token = bearer(sign(githubKey, claims()));
        // 다른 레포로 등록
        mvc.perform(post("/api/v1/iac/runs").header(HttpHeaders.AUTHORIZATION, token)
                        .contentType(MediaType.APPLICATION_JSON).content(RUN_BODY.formatted("Logssey/other", "b".repeat(40))))
                .andExpect(status().isForbidden());
        // 다른 레포의 run 은 없는 것처럼
        long other = jdbc.queryForObject("""
                INSERT INTO iac_runs (repo_id, pr_number, head_sha, trigger_type, status)
                SELECT repo_id, 3, ?, 'PR', 'PLANNING' FROM iac_repos WHERE full_name = 'Logssey/other' RETURNING run_id
                """, Long.class, "c".repeat(40));
        mvc.perform(get("/api/v1/iac/runs/" + other)
                        .header(HttpHeaders.AUTHORIZATION, token))
                .andExpect(status().isNotFound());
        mvc.perform(get("/api/v1/iac/runs/" + other + "/result").header(HttpHeaders.AUTHORIZATION, token))
                .andExpect(status().isNotFound());
        mvc.perform(put("/api/v1/iac/runs/" + other + "/plan").header(HttpHeaders.AUTHORIZATION, token)
                        .contentType("application/gzip").content(IacPlanFixtures.gzipResource("plan-scrubbed.json")))
                .andExpect(status().isNotFound());
        // runs 밖의 IaC API 는 열리지 않는다
        mvc.perform(get("/api/v1/iac/gates")
                        .header(HttpHeaders.AUTHORIZATION, token))
                .andExpect(status().is4xxClientError());
        mvc.perform(post("/api/v1/iac/jobs/enrich-graph/trigger").header(HttpHeaders.AUTHORIZATION, token))
                .andExpect(status().is4xxClientError());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_runs WHERE repo_id = 1", Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_jobs", Long.class)).isZero();
    }

    @Test
    void theDriftWorkflowRegistersOnlyMainBranchChecksAndTheReportWorkflowOnlyPullRequests() throws Exception {
        String drift = token(c -> c.subject(DRIFT_SUBJECT));
        String report = bearer(sign(githubKey, claims()));
        var created = mvc.perform(post("/api/v1/iac/runs").header(HttpHeaders.AUTHORIZATION, drift)
                        .contentType(MediaType.APPLICATION_JSON).content(PUSH_BODY.formatted(REPO, "f".repeat(40))))
                .andExpect(status().isCreated())
                .andReturn();
        long push = Long.parseLong(created.getResponse().getHeader(HttpHeaders.LOCATION).replaceAll(".*/", ""));
        mvc.perform(put("/api/v1/iac/runs/" + push + "/plan").header(HttpHeaders.AUTHORIZATION, drift)
                        .contentType("application/gzip").content(IacPlanFixtures.gzipResource("plan-scrubbed.json")))
                .andExpect(status().isAccepted());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_jobs WHERE kind = 'CHECK_DRIFT'", Long.class)).isEqualTo(1L);
        mvc.perform(get("/api/v1/iac/runs/" + push + "/result").header(HttpHeaders.AUTHORIZATION, drift))
                .andExpect(status().isOk());

        // 서로의 실행 종류는 등록할 수 없다
        mvc.perform(post("/api/v1/iac/runs").header(HttpHeaders.AUTHORIZATION, drift)
                        .contentType(MediaType.APPLICATION_JSON).content(RUN_BODY.formatted(REPO, "1".repeat(40))))
                .andExpect(status().isForbidden());
        mvc.perform(post("/api/v1/iac/runs").header(HttpHeaders.AUTHORIZATION, report)
                        .contentType(MediaType.APPLICATION_JSON).content(PUSH_BODY.formatted(REPO, "2".repeat(40))))
                .andExpect(status().isForbidden());
        // 서로의 실행은 없는 것처럼
        mvc.perform(get("/api/v1/iac/runs/" + push).header(HttpHeaders.AUTHORIZATION, report))
                .andExpect(status().isNotFound());
        mvc.perform(get("/api/v1/iac/runs/" + push + "/result").header(HttpHeaders.AUTHORIZATION, report))
                .andExpect(status().isNotFound());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM iac_runs", Long.class)).isEqualTo(1L);
        assertThat(jdbc.queryForList("SELECT DISTINCT actor_kind FROM iac_audit_events", String.class))
                .containsExactly("CI");
    }

    @Test
    void withoutABearerTokenTheAdminSessionStillRegistersRuns() throws Exception {
        mvc.perform(post("/api/v1/iac/runs").with(csrf()).contentType(MediaType.APPLICATION_JSON)
                        .content(RUN_BODY.formatted(REPO, "d".repeat(40))))
                .andExpect(status().isUnauthorized());
        var login = mvc.perform(post("/api/v1/auth/login").with(csrf()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"loginId\":\"admin\",\"password\":\"admin-pass\"}"))
                .andExpect(status().isOk()).andReturn();
        var session = (MockHttpSession) login.getRequest().getSession(false);
        mvc.perform(post("/api/v1/iac/runs").session(session).with(csrf())
                        .contentType(MediaType.APPLICATION_JSON).content(RUN_BODY.formatted(REPO, "d".repeat(40))))
                .andExpect(status().isCreated());
        mvc.perform(get("/api/v1/iac/runs/1/result").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.number").value(58));
        assertThat(jdbc.queryForList("SELECT DISTINCT actor_kind FROM iac_audit_events", String.class))
                .containsExactly("USER");
    }

    private void expectUnauthenticated(String authorization) throws Exception {
        mvc.perform(post("/api/v1/iac/runs").header(HttpHeaders.AUTHORIZATION, authorization)
                        .contentType(MediaType.APPLICATION_JSON).content(RUN_BODY.formatted(REPO, "e".repeat(40))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }

    private String token(Consumer<JWTClaimsSet.Builder> change) throws JOSEException {
        var claims = claims();
        change.accept(claims);
        return bearer(sign(githubKey, claims));
    }

    /** iac-report (workflow_run, environment iac-app) 의 토큰 */
    private static JWTClaimsSet.Builder claims() {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience("logssey-iac")
                .subject(SUBJECT)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .claim("repository", REPO)
                .claim("repository_owner", "Logssey")
                .claim("environment", "iac-app")
                .claim("event_name", "workflow_run")
                .claim("ref", "refs/heads/main");
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
