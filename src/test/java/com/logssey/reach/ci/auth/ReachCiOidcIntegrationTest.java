package com.logssey.reach.ci.auth;

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;
import java.util.zip.GZIPOutputStream;

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
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import org.testcontainers.postgresql.PostgreSQLContainer;

import tools.jackson.databind.json.JsonMapper;

/**
 * Reach CI 인증 전체 흐름 (11/02 결정 ①~⑥). WireMock 이 GitHub OIDC 공개 키(JWKS)를 주고,
 * 테스트가 만든 키로 서명한 토큰을 보낸다. 세션 요청은 그대로 동작해야 한다
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
        "logssey.reach.ci.repository-owner=Logssey"
})
class ReachCiOidcIntegrationTest {

    private static final String ISSUER = "https://token.actions.githubusercontent.com";
    private static final String COMMIT = "bb4639b".repeat(5) + "00000";
    private static final String DIGEST = "sha256:" + "a6ffffef".repeat(8);
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static final JsonMapper JSON = JsonMapper.builder().build();
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
        properties.add("logssey.reach.ci.oidc.jwk-set-uri", () -> github.baseUrl() + "/.well-known/jwks");
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
        jdbc.execute("TRUNCATE reach_ci_checks, reach_review_history, reach_reviews, reach_evidence, reach_verdicts, "
                + "reach_findings, reach_scans, reach_targets RESTART IDENTITY CASCADE");
        github.stubFor(get(urlPathEqualTo("/.well-known/jwks"))
                .willReturn(okJson(new JWKSet(githubKey.toPublicJWK()).toString())));
    }

    // ---- ② 토큰 검증: 실패하면 401 ----

    @Test
    void invalidTokensAreUnauthenticated() throws Exception {
        String body = prBody("service-backend", 123);
        expect(401, createWith("Bearer not-a-jwt", body));
        expect(401, createWith(bearer(sign(otherKey, prClaims())), body));                       // 서명 키가 다름
        expect(401, create(claims -> claims.expirationTime(Date.from(Instant.now().minusSeconds(120))), body));
        expect(401, create(claims -> claims.issuer("https://example.com"), body));
        expect(401, create(claims -> claims.audience("sts.amazonaws.com"), body));
        expect(401, create(claims -> claims.claim("repository", null), body));
        expect(401, create(claims -> claims.claim("repository", "service-backend"), body));      // 소유자 없음
        expect(401, create(claims -> claims.claim("event_name", null), body));
        expect(401, create(claims -> claims.claim("ref", null), body));
        assertThat(count("reach_ci_checks")).isZero();
    }

    // ---- ③④ PR 검사 → 결과 조회 → 업로드 ----

    @Test
    void pullRequestCheckFromCiIsRecordedAsCiAndOnlyThatRepositoryUploads() throws Exception {
        var created = mvc.perform(create(claims -> { }, prBody("service-backend", 123)))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.mode").value("PR"))
                .andReturn();
        long checkId = JSON.readTree(created.getResponse().getContentAsString()).get("id").asLong();

        // 스캔은 CI가 요청한 것으로 남고, 멱등 범위는 토큰의 레포다
        assertThat(jdbc.queryForMap("SELECT s.requested_by_kind, s.requested_by_user_id, s.requested_by_repository, "
                + "s.requested_by_subject, c.idempotency_scope FROM reach_ci_checks c JOIN reach_scans s USING (scan_id)"))
                .containsEntry("requested_by_kind", "CI")
                .containsEntry("requested_by_user_id", null)
                .containsEntry("requested_by_repository", "Logssey/service-backend")
                .containsEntry("requested_by_subject", "repo:Logssey/service-backend:pull_request")
                .containsEntry("idempotency_scope", "CI:Logssey/service-backend");

        // 같은 키로 다시 보내면 같은 검사 (러너 재실행)
        mvc.perform(create(claims -> { }, prBody("service-backend", 123)))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.id").value(checkId))
                .andExpect(result -> assertThat(result.getResponse().getHeader("Idempotent-Replayed")).isEqualTo("true"));

        // 결과 조회: 만든 레포의 토큰, 대시보드 세션은 되고 다른 레포 토큰은 403
        expect(200, read(checkId, prClaims()));
        expect(200, MockMvcRequestBuilders.get("/api/v1/reach/ci/checks/" + checkId).session(admin()));
        expect(403, read(checkId, frontendClaims()));
        expect(404, read(999, prClaims()));

        // 업로드: 다른 레포 토큰은 본문을 보기 전에 403, 만든 레포 토큰은 202
        expect(403, upload(checkId, frontendClaims()));
        mvc.perform(upload(checkId, prClaims()))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.scanStatus").value("SUCCEEDED"));

        // 대시보드 화면 API가 CI 요청자를 보여 준다
        long scanId = jdbc.queryForObject("SELECT scan_id FROM reach_ci_checks WHERE check_id = ?", Long.class, checkId);
        mvc.perform(MockMvcRequestBuilders.get("/api/v1/reach/scans/" + scanId).session(admin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.requestedBy.kind").value("CI"))
                .andExpect(jsonPath("$.requestedBy.repository").value("Logssey/service-backend"));
    }

    @Test
    void imageCheckFromTheDefaultBranch() throws Exception {
        expect(202, create(this::mainBranch, imageBody("logssey/reused-api")));
        expect(403, create(claims -> claims.claim("ref", "refs/heads/develop").claim("event_name", "push"),
                imageBody("logssey/reused-api")));
        expect(403, create(this::mainBranch, imageBody("logssey/reused-web")));   // 다른 레포의 이미지
    }

    // ---- ③ 권한 밖: 403 ----

    @Test
    void ciTokensCannotActForOtherRepositoriesOrOutsideCiPaths() throws Exception {
        expect(403, create(claims -> claims.claim("repository", "Logssey/dashboard-backend")
                .subject("repo:Logssey/dashboard-backend:pull_request"), prBody("dashboard-backend", 123)));
        expect(403, create(claims -> { }, prBody("service-frontend", 123)));               // 본문이 다른 레포
        expect(403, create(claims -> { }, prBody("service-backend", 124)));                // 다른 PR 번호
        expect(403, create(claims -> claims.claim("event_name", "push").claim("ref", "refs/heads/main"),
                prBody("service-backend", 123)));                                         // PR 이벤트가 아님
        expect(400, create(claims -> { }, "{\"mode\":\"PR\"}"));                           // 형식 검사가 먼저
        assertThat(count("reach_ci_checks")).isZero();

        // 사람이 만든 검사에는 CI가 올리지 못한다
        var byUser = mvc.perform(post("/api/v1/reach/ci/checks").session(admin()).with(csrf())
                        .header("Idempotency-Key", "user-1").contentType(MediaType.APPLICATION_JSON)
                        .content(prBody("service-backend", 123)))
                .andExpect(status().isAccepted()).andReturn();
        long userCheck = JSON.readTree(byUser.getResponse().getContentAsString()).get("id").asLong();
        expect(403, upload(userCheck, prClaims()));

        // 유효한 CI 토큰이라도 CI 경로 밖 Reach API는 403, Reach 밖은 기존 체인(세션 없음)이 401
        expect(403, MockMvcRequestBuilders.get("/api/v1/reach/findings").header(HttpHeaders.AUTHORIZATION, bearer(sign(githubKey, prClaims()))));
        expect(403, post("/api/v1/reach/scans").header(HttpHeaders.AUTHORIZATION, bearer(sign(githubKey, prClaims())))
                .contentType(MediaType.APPLICATION_JSON).content("{}"));
        expect(401, MockMvcRequestBuilders.get("/api/v1/overview/summary").header(HttpHeaders.AUTHORIZATION, bearer(sign(githubKey, prClaims()))));
    }

    @Test
    void sessionRequestsStillWorkWithoutABearerToken() throws Exception {
        expect(401, MockMvcRequestBuilders.get("/api/v1/reach/ci/checks/1"));
        expect(403, post("/api/v1/reach/ci/checks").session(admin())                      // 세션 요청은 CSRF 그대로
                .header("Idempotency-Key", "k").contentType(MediaType.APPLICATION_JSON).content(prBody("service-backend", 1)));
        expect(200, MockMvcRequestBuilders.get("/api/v1/reach/apps").session(admin()));
    }

    // ---- 도우미 ----

    private JWTClaimsSet.Builder prClaims() {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience("logssey-reach")
                .subject("repo:Logssey/service-backend:pull_request")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .claim("repository", "Logssey/service-backend")
                .claim("repository_owner", "Logssey")
                .claim("event_name", "pull_request")
                .claim("ref", "refs/pull/123/merge");
    }

    private JWTClaimsSet.Builder frontendClaims() {
        return prClaims().subject("repo:Logssey/service-frontend:pull_request")
                .claim("repository", "Logssey/service-frontend");
    }

    private void mainBranch(JWTClaimsSet.Builder claims) {
        claims.subject("repo:Logssey/service-backend:ref:refs/heads/main")
                .claim("event_name", "workflow_run").claim("ref", "refs/heads/main");
    }

    private static String sign(RSAKey key, JWTClaimsSet.Builder claims) throws JOSEException {
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims.build());
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    private static String bearer(String token) {
        return "Bearer " + token;
    }

    private MockHttpServletRequestBuilder create(Consumer<JWTClaimsSet.Builder> change, String body) throws JOSEException {
        var claims = prClaims();
        change.accept(claims);
        return createWith(bearer(sign(githubKey, claims)), body);
    }

    private static MockHttpServletRequestBuilder createWith(String authorization, String body) {
        return post("/api/v1/reach/ci/checks").header(HttpHeaders.AUTHORIZATION, authorization)
                .header("Idempotency-Key", "service-backend-ci-1")
                .contentType(MediaType.APPLICATION_JSON).content(body);
    }

    private static MockHttpServletRequestBuilder read(long checkId, JWTClaimsSet.Builder claims) throws JOSEException {
        return MockMvcRequestBuilders.get("/api/v1/reach/ci/checks/" + checkId)
                .header(HttpHeaders.AUTHORIZATION, bearer(sign(githubKey, claims)));
    }

    private static MockHttpServletRequestBuilder upload(long checkId, JWTClaimsSet.Builder claims) throws Exception {
        return put("/api/v1/reach/ci/checks/" + checkId + "/results")
                .header(HttpHeaders.AUTHORIZATION, bearer(sign(githubKey, claims)))
                .header("Content-Encoding", "gzip")
                .contentType(MediaType.APPLICATION_JSON)
                .content(gzip(emptyBundle()));
    }

    private MockHttpSession admin() throws Exception {
        var login = mvc.perform(post("/api/v1/auth/login").with(csrf()).contentType(MediaType.APPLICATION_JSON)
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

    private static String prBody(String repository, int number) {
        return """
                {"mode":"PR","repository":"%s","headCommit":"%s",
                 "pullRequest":{"number":%d,"baseRef":"main","headRef":"feature"},
                 "target":{"type":"REPO","repo":{"name":"%s","commit":"%s"}}}
                """.formatted(repository, COMMIT, number, repository, COMMIT);
    }

    private static String imageBody(String image) {
        return """
                {"mode":"IMAGE_BUILD","repository":"service-backend","headCommit":"%s",
                 "target":{"type":"IMAGE","image":{"repository":"%s","digest":"%s"}}}
                """.formatted(COMMIT, image, DIGEST);
    }

    /** Finding 없이 끝난 결과 묶음 */
    private static Map<String, Object> emptyBundle() {
        var bundle = new LinkedHashMap<String, Object>();
        bundle.put("sbom", Map.of("bomFormat", "CycloneDX"));
        bundle.put("matches", Map.of("trivy", Map.of()));
        bundle.put("verdicts", java.util.List.of());
        bundle.put("reachResult", Map.of("facts", java.util.List.of()));
        bundle.put("tools", Map.of("trivy", "0.69.3", "reach", "v0"));
        bundle.put("analysis", Map.of("appClasses", 1));
        bundle.put("stages", java.util.List.of(Map.of("name", "sbom", "status", "succeeded", "durationSeconds", 1)));
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
