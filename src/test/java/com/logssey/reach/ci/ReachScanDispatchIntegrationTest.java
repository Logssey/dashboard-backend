package com.logssey.reach.ci;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.zip.GZIPOutputStream;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.junit.jupiter.api.AfterAll;
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
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.testcontainers.postgresql.PostgreSQLContainer;

import tools.jackson.databind.json.JsonMapper;

/**
 * API-01 → workflow_dispatch → 러너 업로드 (ARD AD-18 ③). WireMock 하나가 GitHub API(설치·토큰·dispatch)와
 * GitHub OIDC 공개 키(JWKS)를 맡는다. 앱 개인 키와 OIDC 키는 테스트가 만든다
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
        "logssey.reach.apps[0].code=API",
        "logssey.reach.apps[0].repo=service-backend",
        "logssey.reach.apps[0].image=logssey/reused-api",
        "logssey.reach.apps[1].code=WEB",
        "logssey.reach.apps[1].repo=service-frontend",
        "logssey.reach.apps[1].image=logssey/reused-web",
        "logssey.reach.ci.repository-owner=Logssey",
        "logssey.reach.dispatch.app-id=123456"
})
class ReachScanDispatchIntegrationTest {

    private static final String ISSUER = "https://token.actions.githubusercontent.com";
    private static final String COMMIT = "bb4639b".repeat(5) + "00000";
    private static final String DIGEST = "sha256:" + "a6ffffef".repeat(8);
    private static final String DISPATCH = "/repos/Logssey/service-backend/actions/workflows/reach.yml/dispatches";
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final RSAKey APP_KEY;
    private static final RSAKey OIDC_KEY;

    static {
        POSTGRES.start();
        try {
            APP_KEY = new RSAKeyGenerator(2048).generate();
            OIDC_KEY = new RSAKeyGenerator(2048).keyID("github").generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    @RegisterExtension
    static WireMockExtension github = WireMockExtension.newInstance().options(wireMockConfig().dynamicPort()).build();

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry properties) throws JOSEException {
        properties.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        properties.add("spring.datasource.username", POSTGRES::getUsername);
        properties.add("spring.datasource.password", POSTGRES::getPassword);
        properties.add("logssey.reach.ci.oidc.jwk-set-uri", () -> github.baseUrl() + "/.well-known/jwks");
        properties.add("logssey.reach.dispatch.api-base-url", github::baseUrl);
        String pem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                        .encodeToString(APP_KEY.toPrivateKey().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
        properties.add("logssey.reach.dispatch.private-key", () -> pem);
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
        jdbc.execute("TRUNCATE reach_ci_checks, reach_review_history, reach_reviews, reach_evidence, reach_verdicts, "
                + "reach_findings, reach_scans, reach_targets RESTART IDENTITY CASCADE");
        github.resetAll();
        github.stubFor(get(urlPathEqualTo("/.well-known/jwks"))
                .willReturn(okJson(new JWKSet(OIDC_KEY.toPublicJWK()).toString())));
        github.stubFor(get(urlPathEqualTo("/repos/Logssey/service-backend/installation"))
                .willReturn(okJson("{\"id\":42}")));
        github.stubFor(post(urlPathEqualTo("/app/installations/42/access_tokens"))
                .willReturn(aResponse().withStatus(201).withHeader("Content-Type", "application/json")
                        .withBody("{\"token\":\"ghs_installation\",\"expires_at\":\"2030-01-01T00:00:00Z\"}")));
        github.stubFor(post(urlPathEqualTo(DISPATCH)).willReturn(aResponse().withStatus(204)));
    }

    @Test
    void scanRequestDispatchesTheWorkflowAndTheDispatchedRunUploads() throws Exception {
        var created = mvc.perform(scanRequest("s1", repoBody()))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.scanStatus").value("QUEUED"))
                .andReturn();
        long scanId = JSON.readTree(created.getResponse().getContentAsString()).get("id").asLong();
        long checkId = jdbc.queryForObject("SELECT check_id FROM reach_ci_checks WHERE scan_id = ?", Long.class, scanId);

        // 앱 JWT: 앱 개인 키로 서명, iss = 앱 ID
        var installation = github.findAll(getRequestedFor(urlPathEqualTo("/repos/Logssey/service-backend/installation")));
        assertThat(installation).hasSize(1);
        var appJwt = SignedJWT.parse(installation.get(0).getHeader(HttpHeaders.AUTHORIZATION).substring("Bearer ".length()));
        assertThat(appJwt.verify(new RSASSAVerifier(APP_KEY.toRSAPublicKey()))).isTrue();
        assertThat(appJwt.getJWTClaimsSet().getIssuer()).isEqualTo("123456");
        assertThat(appJwt.getJWTClaimsSet().getExpirationTime()).isBefore(Date.from(Instant.now().plusSeconds(601)));

        // 설치 토큰은 그 레포·actions:write만, dispatch는 그 토큰으로 기본 브랜치에
        github.verify(postRequestedFor(urlPathEqualTo("/app/installations/42/access_tokens"))
                .withRequestBody(equalToJson("{\"repositories\":[\"service-backend\"],\"permissions\":{\"actions\":\"write\"}}")));
        github.verify(postRequestedFor(urlPathEqualTo(DISPATCH))
                .withHeader(HttpHeaders.AUTHORIZATION, equalTo("Bearer ghs_installation"))
                .withRequestBody(equalToJson("""
                        {"ref":"main","inputs":{"check_id":"%d","target_type":"REPO","commit":"%s","path":"",
                         "image_repository":"","image_digest":""}}""".formatted(checkId, COMMIT))));

        // 같은 키로 다시 보내면 같은 스캔이고 다시 띄우지 않는다
        mvc.perform(scanRequest("s1", repoBody()))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.id").value(scanId));
        github.verify(1, postRequestedFor(urlPathEqualTo(DISPATCH)));

        // 띄운 실행(workflow_dispatch, main)의 그 레포 토큰만 검사를 보고 올린다
        expect(403, read(checkId, claims -> claims.claim("event_name", "pull_request").claim("ref", "refs/pull/1/merge")));
        expect(403, read(checkId, claims -> claims.claim("ref", "refs/heads/feature")));
        expect(403, read(checkId, claims -> claims.claim("repository", "Logssey/service-frontend")
                .subject("repo:Logssey/service-frontend:ref:refs/heads/main")));
        expect(403, upload(checkId, claims -> claims.claim("repository", "Logssey/service-frontend")
                .subject("repo:Logssey/service-frontend:ref:refs/heads/main")));
        mvc.perform(read(checkId, claims -> { }))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mode").value("MANUAL"))
                .andExpect(jsonPath("$.repository").value("service-backend"));
        mvc.perform(upload(checkId, claims -> { }))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.scanStatus").value("SUCCEEDED"));
    }

    @Test
    void imageScanRunsInTheRepositoryOfTheImageApp() throws Exception {
        github.stubFor(get(urlPathEqualTo("/repos/Logssey/service-frontend/installation")).willReturn(okJson("{\"id\":42}")));
        github.stubFor(post(urlPathEqualTo("/repos/Logssey/service-frontend/actions/workflows/reach.yml/dispatches"))
                .willReturn(aResponse().withStatus(204)));
        mvc.perform(scanRequest("i1", """
                        {"target":{"type":"IMAGE","image":{"repository":"logssey/reused-web","digest":"%s"}}}
                        """.formatted(DIGEST)))
                .andExpect(status().isAccepted());
        github.verify(postRequestedFor(urlPathEqualTo("/repos/Logssey/service-frontend/actions/workflows/reach.yml/dispatches"))
                .withRequestBody(equalToJson("""
                        {"ref":"main","inputs":{"check_id":"1","target_type":"IMAGE","commit":"","path":"",
                         "image_repository":"logssey/reused-web","image_digest":"%s"}}""".formatted(DIGEST))));
    }

    @Test
    void whenGitHubFailsTheRequestIs503AndLeavesNoQueuedScan() throws Exception {
        github.stubFor(post(urlPathEqualTo(DISPATCH)).willReturn(aResponse().withStatus(422)
                .withBody("{\"message\":\"Workflow does not have 'workflow_dispatch' trigger\"}")));
        mvc.perform(scanRequest("f1", repoBody()))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.code").value("UNAVAILABLE"))
                .andExpect(jsonPath("$.details.dependency").value("github"));
        assertThat(count("reach_scans") + count("reach_ci_checks") + count("reach_targets")).isZero();

        // 그 레포에 앱이 설치되지 않았거나(설치 404) 기본 브랜치에 워크플로가 없으면(dispatch 404) 다시 해도 같아 422
        github.stubFor(get(urlPathEqualTo("/repos/Logssey/service-backend/installation"))
                .willReturn(aResponse().withStatus(404)));
        mvc.perform(scanRequest("f1", repoBody()))
                .andExpect(status().is(422))
                .andExpect(jsonPath("$.code").value("UNPROCESSABLE"))
                .andExpect(jsonPath("$.message").value(org.hamcrest.Matchers.startsWith("RUNNER_NOT_INSTALLED")));
        github.stubFor(get(urlPathEqualTo("/repos/Logssey/service-backend/installation")).willReturn(okJson("{\"id\":42}")));
        github.stubFor(post(urlPathEqualTo(DISPATCH)).willReturn(aResponse().withStatus(404)));
        expect(422, scanRequest("f1", repoBody()));
        assertThat(count("reach_scans") + count("reach_ci_checks") + count("reach_targets")).isZero();

        // GitHub에 닿지 않으면 503
        github.stubFor(get(urlPathEqualTo("/repos/Logssey/service-backend/installation"))
                .willReturn(aResponse().withFault(com.github.tomakehurst.wiremock.http.Fault.CONNECTION_RESET_BY_PEER)));
        expect(503, scanRequest("f1", repoBody()));
        assertThat(count("reach_scans")).isZero();

        // GitHub이 돌아오면 같은 키로 다시 요청해 띄운다
        github.stubFor(get(urlPathEqualTo("/repos/Logssey/service-backend/installation")).willReturn(okJson("{\"id\":42}")));
        github.stubFor(post(urlPathEqualTo(DISPATCH)).willReturn(aResponse().withStatus(204)));
        expect(202, scanRequest("f1", repoBody()));
        assertThat(count("reach_scans")).isEqualTo(1);
    }

    // ---- 도우미 ----

    private MockHttpServletRequestBuilder scanRequest(String key, String body) throws Exception {
        return MockMvcRequestBuilders.post("/api/v1/reach/scans").session(admin()).with(csrf())
                .header("Idempotency-Key", key).contentType(MediaType.APPLICATION_JSON).content(body);
    }

    private static String repoBody() {
        return "{\"target\":{\"type\":\"REPO\",\"repo\":{\"name\":\"service-backend\",\"commit\":\"%s\"}}}".formatted(COMMIT);
    }

    /** 서버가 띄운 실행의 토큰: workflow_dispatch, 기본 브랜치 */
    private static JWTClaimsSet.Builder dispatchedClaims() {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience("logssey-reach")
                .subject("repo:Logssey/service-backend:ref:refs/heads/main")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .claim("repository", "Logssey/service-backend")
                .claim("repository_owner", "Logssey")
                .claim("event_name", "workflow_dispatch")
                .claim("ref", "refs/heads/main");
    }

    private static String bearer(Consumer<JWTClaimsSet.Builder> change) throws JOSEException {
        var claims = dispatchedClaims();
        change.accept(claims);
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(OIDC_KEY.getKeyID()).build(), claims.build());
        jwt.sign(new RSASSASigner(OIDC_KEY));
        return "Bearer " + jwt.serialize();
    }

    private static MockHttpServletRequestBuilder read(long checkId, Consumer<JWTClaimsSet.Builder> change) throws JOSEException {
        return MockMvcRequestBuilders.get("/api/v1/reach/ci/checks/" + checkId)
                .header(HttpHeaders.AUTHORIZATION, bearer(change));
    }

    private static MockHttpServletRequestBuilder upload(long checkId, Consumer<JWTClaimsSet.Builder> change) throws Exception {
        return put("/api/v1/reach/ci/checks/" + checkId + "/results")
                .header(HttpHeaders.AUTHORIZATION, bearer(change))
                .header("Content-Encoding", "gzip")
                .contentType(MediaType.APPLICATION_JSON)
                .content(gzip(emptyBundle()));
    }

    private MockHttpSession admin() throws Exception {
        var login = mvc.perform(MockMvcRequestBuilders.post("/api/v1/auth/login").with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"loginId\":\"admin\",\"password\":\"admin-pass\"}"))
                .andExpect(status().isOk()).andReturn();
        return (MockHttpSession) login.getRequest().getSession(false);
    }

    private void expect(int status, MockHttpServletRequestBuilder request) throws Exception {
        mvc.perform(request).andExpect(status().is(status));
    }

    private long count(String table) {
        return jdbc.queryForObject("SELECT count(*) FROM " + table, Long.class);
    }

    /** Finding 없이 끝난 결과 묶음 */
    private static Map<String, Object> emptyBundle() {
        var bundle = new LinkedHashMap<String, Object>();
        bundle.put("sbom", Map.of("bomFormat", "CycloneDX"));
        bundle.put("matches", Map.of("trivy", Map.of()));
        bundle.put("verdicts", List.of());
        bundle.put("reachResult", Map.of("facts", List.of()));
        bundle.put("tools", Map.of("trivy", "0.69.3", "reach", "v0"));
        bundle.put("analysis", Map.of("appClasses", 1));
        bundle.put("stages", List.of(Map.of("name", "sbom", "status", "succeeded", "durationSeconds", 1)));
        return bundle;
    }

    private static byte[] gzip(Object value) throws IOException {
        var out = new ByteArrayOutputStream();
        try (var gzip = new GZIPOutputStream(out)) {
            gzip.write(JSON.writeValueAsString(value).getBytes(StandardCharsets.UTF_8));
        }
        return out.toByteArray();
    }
}
