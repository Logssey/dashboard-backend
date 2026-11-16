package com.logssey.reach.auth;

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

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.function.Consumer;

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

/**
 * L1 수집기 토큰(클러스터 서비스 계정) 전체 흐름. WireMock 이 클러스터와 GitHub 의 공개 키(JWKS)를 주고,
 * 테스트가 만든 키로 서명한 토큰을 보낸다. 같은 Bearer 체인에서 CI 토큰과 섞이지 않아야 하고, 세션 업로드는 그대로여야 한다
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
        "logssey.reach.l1.cluster=reused-prod",
        "logssey.reach.l1.namespaces=reused",
        "logssey.reach.ci.repository-owner=Logssey",
        "logssey.reach.l1.collector.issuer=" + ReachL1CollectorTokenIntegrationTest.CLUSTER_ISSUER
})
class ReachL1CollectorTokenIntegrationTest {

    static final String CLUSTER_ISSUER = "https://k8s-oidc.example.test";
    private static final String GITHUB_ISSUER = "https://token.actions.githubusercontent.com";
    private static final String COLLECTOR = "system:serviceaccount:reach:reach-l1-collector";
    private static final String DIGEST = "sha256:" + "a6ffffef".repeat(8);
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:18.6");
    private static RSAKey clusterKey;
    private static RSAKey otherKey;
    private static RSAKey githubKey;

    static {
        POSTGRES.start();
    }

    @RegisterExtension
    static WireMockExtension jwks = WireMockExtension.newInstance().options(wireMockConfig().dynamicPort()).build();

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry properties) {
        properties.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        properties.add("spring.datasource.username", POSTGRES::getUsername);
        properties.add("spring.datasource.password", POSTGRES::getPassword);
        properties.add("logssey.reach.l1.collector.jwk-set-uri", () -> jwks.baseUrl() + "/openid/v1/jwks");
        properties.add("logssey.reach.ci.oidc.jwk-set-uri", () -> jwks.baseUrl() + "/.well-known/jwks");
    }

    @BeforeAll
    static void keys() throws JOSEException {
        clusterKey = new RSAKeyGenerator(2048).keyID("cluster").generate();
        otherKey = new RSAKeyGenerator(2048).keyID("cluster").generate();   // 같은 kid, 다른 키
        githubKey = new RSAKeyGenerator(2048).keyID("github").generate();
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
        jdbc.execute("TRUNCATE reach_workloads, reach_workload_observations RESTART IDENTITY CASCADE");
        jwks.stubFor(get(urlPathEqualTo("/openid/v1/jwks"))
                .willReturn(okJson(new JWKSet(clusterKey.toPublicJWK()).toString())));
        jwks.stubFor(get(urlPathEqualTo("/.well-known/jwks"))
                .willReturn(okJson(new JWKSet(githubKey.toPublicJWK()).toString())));
    }

    @Test
    void collectorUploadsWorkloadsWithItsServiceAccountToken() throws Exception {
        mvc.perform(upload(collector(claims -> { }), inventory("reused")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.namespace").value("reused"))
                .andExpect(jsonPath("$.workloads").value(1));

        assertThat(jdbc.queryForMap("SELECT source, reported_by FROM reach_workload_observations"))
                .containsEntry("source", "CLUSTER_READER").containsEntry("reported_by", COLLECTOR);
        assertThat(jdbc.queryForObject("SELECT image_digest FROM reach_workloads", String.class)).isEqualTo(DIGEST);

        // 범위 밖 네임스페이스는 토큰이 맞아도 400 (수동 업로드와 같은 검사)
        expect(400, upload(collector(claims -> { }), inventory("other")));
    }

    @Test
    void invalidCollectorTokensAreUnauthenticated() throws Exception {
        String body = inventory("reused");
        expect(401, upload("Bearer not-a-jwt", body));
        expect(401, upload(bearer(sign(otherKey, collectorClaims())), body));                      // 서명 키가 다름
        expect(401, upload(collector(claims -> claims.expirationTime(Date.from(Instant.now().minusSeconds(120)))), body));
        expect(401, upload(collector(claims -> claims.audience("https://kubernetes.default.svc")), body));
        expect(401, upload(collector(claims -> claims.issuer("https://other-cluster.example.test")), body));   // 모르는 발급자
        expect(401, upload(collector(claims -> claims.subject(null)), body));
        assertThat(count()).isZero();
    }

    @Test
    void otherServiceAccountsOfTheClusterCannotUpload() throws Exception {
        // 같은 aud 토큰은 클러스터의 어떤 파드든 받을 수 있다. 수집기 서비스 계정만 올린다
        expect(403, upload(collector(claims -> claims.subject("system:serviceaccount:reused:default")), inventory("reused")));
        assertThat(count()).isZero();
    }

    @Test
    void collectorAndCiTokensStayInTheirOwnPaths() throws Exception {
        String collectorToken = collector(claims -> { });
        expect(403, MockMvcRequestBuilders.get("/api/v1/reach/workloads").header(HttpHeaders.AUTHORIZATION, collectorToken));
        expect(403, MockMvcRequestBuilders.get("/api/v1/reach/findings").header(HttpHeaders.AUTHORIZATION, collectorToken));
        expect(403, MockMvcRequestBuilders.get("/api/v1/reach/ci/checks/1").header(HttpHeaders.AUTHORIZATION, collectorToken));
        expect(403, post("/api/v1/reach/ci/checks").header(HttpHeaders.AUTHORIZATION, collectorToken)
                .contentType(MediaType.APPLICATION_JSON).content("{}"));

        // 유효한 GitHub CI 토큰으로 L1 업로드는 403
        expect(403, upload(bearer(sign(githubKey, githubClaims())), inventory("reused")));
        assertThat(count()).isZero();
    }

    @Test
    void adminSessionUploadStillWorks() throws Exception {
        mvc.perform(put("/api/v1/reach/l1/workloads").session(admin()).with(csrf())
                        .contentType(MediaType.APPLICATION_JSON).content(inventory("reused")))
                .andExpect(status().isOk());
        assertThat(jdbc.queryForObject("SELECT source FROM reach_workload_observations", String.class)).isEqualTo("MANUAL");
        expect(401, put("/api/v1/reach/l1/workloads").with(csrf())
                .contentType(MediaType.APPLICATION_JSON).content(inventory("reused")));
    }

    // ---- 도우미 ----

    private static JWTClaimsSet.Builder collectorClaims() {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
                .issuer(CLUSTER_ISSUER)
                .audience("logssey-reach-l1")
                .subject(COLLECTOR)
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(600)));
    }

    private static JWTClaimsSet.Builder githubClaims() {
        Instant now = Instant.now();
        return new JWTClaimsSet.Builder()
                .issuer(GITHUB_ISSUER)
                .audience("logssey-reach")
                .subject("repo:Logssey/service-backend:pull_request")
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .claim("repository", "Logssey/service-backend")
                .claim("event_name", "pull_request")
                .claim("ref", "refs/pull/123/merge");
    }

    private static String collector(Consumer<JWTClaimsSet.Builder> change) throws JOSEException {
        var claims = collectorClaims();
        change.accept(claims);
        return bearer(sign(clusterKey, claims));
    }

    private static String sign(RSAKey key, JWTClaimsSet.Builder claims) throws JOSEException {
        var jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(key.getKeyID()).build(), claims.build());
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    private static String bearer(String token) {
        return "Bearer " + token;
    }

    private static MockHttpServletRequestBuilder upload(String authorization, String body) {
        return put("/api/v1/reach/l1/workloads").header(HttpHeaders.AUTHORIZATION, authorization)
                .contentType(MediaType.APPLICATION_JSON).content(body);
    }

    private static String inventory(String namespace) {
        return """
                {"cluster":"reused-prod","namespace":"%s","observedAt":"%s",
                 "workloads":[{"kind":"Deployment","name":"reused-api",
                   "containers":[{"name":"api","image":"logssey/reused-api:1","imageDigest":"%s","readyReplicas":2}]}]}
                """.formatted(namespace, OffsetDateTime.now(ZoneOffset.UTC).withNano(0), DIGEST);
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

    private long count() {
        return jdbc.queryForObject("SELECT count(*) FROM reach_workload_observations", Long.class);
    }
}
