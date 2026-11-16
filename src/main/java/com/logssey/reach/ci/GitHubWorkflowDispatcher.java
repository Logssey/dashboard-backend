package com.logssey.reach.ci;

import java.io.ByteArrayOutputStream;
import java.net.http.HttpClient;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;

import com.logssey.reach.ci.auth.ReachCiProperties;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * GitHub App으로 서비스 레포의 Reach 워크플로를 workflow_dispatch로 띄운다 (ARD AD-18 ③, API-01).
 *
 * 1. 앱 개인 키로 서명한 JWT(10분)로 그 레포에 설치된 앱의 설치 ID를 찾는다
 * 2. 그 레포·actions:write만 담은 설치 토큰(1시간)을 받는다
 * 3. 기본 브랜치(logssey.reach.ci.default-branch)의 워크플로를 inputs로 띄운다
 *
 * 토큰은 요청마다 새로 받고 저장하지 않는다(스캔 요청은 사람이 누를 때만이라 드물다).
 * GitHub이 실패하거나 응답이 없으면 ReachUnavailableException(503)이고 오류 본문은 로그에만 남긴다
 */
@Component
class GitHubWorkflowDispatcher implements ReachScanDispatcher {

    private static final Logger log = LoggerFactory.getLogger(GitHubWorkflowDispatcher.class);
    private static final String DEPENDENCY = "github";

    private final ReachDispatchProperties properties;
    private final ReachCiProperties ci;
    private final RSAPrivateKey key;
    private final RestClient client;

    GitHubWorkflowDispatcher(ReachDispatchProperties properties, ReachCiProperties ci) {
        this.properties = properties;
        this.ci = ci;
        // 키가 잘못됐으면 첫 요청이 아니라 기동 때 알린다
        this.key = properties.open() ? privateKey(properties.privateKey()) : null;
        var http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        var factory = new JdkClientHttpRequestFactory(http);
        factory.setReadTimeout(Duration.ofSeconds(10));
        this.client = RestClient.builder()
                .baseUrl(properties.apiBaseUrl())
                .requestFactory(factory)
                .defaultHeader("Accept", "application/vnd.github+json")
                .defaultHeader("X-GitHub-Api-Version", "2022-11-28")
                .build();
    }

    @Override
    public boolean enabled() {
        return key != null && ci.open();
    }

    @Override
    public void dispatch(String repository, Map<String, String> inputs) {
        if (!enabled()) throw new IllegalStateException("dispatch is not configured");
        String owner = ci.repositoryOwner();
        try {
            String jwt = appJwt();
            var installation = client.get()
                    .uri("/repos/{owner}/{repo}/installation", owner, repository)
                    .headers(h -> h.setBearerAuth(jwt))
                    .exchange((request, response) -> body(response.getStatusCode(), "installation",
                            () -> response.bodyTo(Map.class)));
            Object installationId = installation.get("id");

            var token = client.post()
                    .uri("/app/installations/{id}/access_tokens", installationId)
                    .headers(h -> h.setBearerAuth(jwt))
                    .body(Map.of("repositories", List.of(repository), "permissions", Map.of("actions", "write")))
                    .exchange((request, response) -> body(response.getStatusCode(), "access token",
                            () -> response.bodyTo(Map.class)));
            String installationToken = String.valueOf(token.get("token"));

            client.post()
                    .uri("/repos/{owner}/{repo}/actions/workflows/{workflow}/dispatches",
                            owner, repository, properties.workflow())
                    .headers(h -> h.setBearerAuth(installationToken))
                    .body(Map.of("ref", ci.defaultBranch(), "inputs", inputs))
                    .exchange((request, response) -> body(response.getStatusCode(), "dispatch", () -> Map.of()));
            log.info("Reach scan dispatched: repository={}/{} workflow={} checkId={}",
                    owner, repository, properties.workflow(), inputs.get("check_id"));
        } catch (RestClientException | JOSEException e) {
            log.warn("Reach scan dispatch failed: repository={}/{} error={}", owner, repository, e.toString());
            throw new ReachUnavailableException(DEPENDENCY, e.getClass().getSimpleName());
        }
    }

    private interface Body {
        Map<?, ?> read();
    }

    /** 2xx가 아니면 503. GitHub 오류 본문은 비밀값이 없지만 길 수 있어 상태 코드만 남긴다 */
    private static Map<?, ?> body(HttpStatusCode status, String step, Body body) {
        if (!status.is2xxSuccessful()) {
            log.warn("Reach scan dispatch failed at {}: HTTP {}", step, status.value());
            throw new ReachUnavailableException(DEPENDENCY, step + " HTTP " + status.value());
        }
        Map<?, ?> value = body.read();
        if (value == null) throw new ReachUnavailableException(DEPENDENCY, step + " empty body");
        return value;
    }

    /** GitHub App JWT. 시계 차이를 견디게 발급 시각을 60초 앞당기고 수명은 GitHub 한도(10분)보다 짧게 둔다 */
    private String appJwt() throws JOSEException {
        Instant now = Instant.now();
        var claims = new JWTClaimsSet.Builder()
                .issuer(properties.appId())
                .issueTime(Date.from(now.minusSeconds(60)))
                .expirationTime(Date.from(now.plusSeconds(540)))
                .build();
        var jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims);
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    /** GitHub이 주는 PKCS#1("RSA PRIVATE KEY")과 변환한 PKCS#8("PRIVATE KEY") 둘 다 받는다 */
    static RSAPrivateKey privateKey(String pem) {
        boolean pkcs1 = pem.contains("BEGIN RSA PRIVATE KEY");
        String base64 = pem.replaceAll("-----(BEGIN|END) [A-Z ]+-----", "").replaceAll("\\s", "");
        try {
            byte[] der = Base64.getDecoder().decode(base64);
            var spec = new PKCS8EncodedKeySpec(pkcs1 ? pkcs8(der) : der);
            return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (IllegalArgumentException | GeneralSecurityException | ClassCastException e) {
            throw new IllegalStateException("logssey.reach.dispatch.private-key is not an RSA private key in PEM", e);
        }
    }

    /** PKCS#1 RSAPrivateKey를 PKCS#8 PrivateKeyInfo로 감싼다: SEQUENCE { 0, rsaEncryption, OCTET STRING pkcs1 } */
    private static byte[] pkcs8(byte[] pkcs1) {
        byte[] version = {0x02, 0x01, 0x00};
        byte[] algorithm = {0x30, 0x0d, 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d,
                0x01, 0x01, 0x01, 0x05, 0x00};
        byte[] octets = der(0x04, pkcs1);
        var content = new ByteArrayOutputStream();
        content.writeBytes(version);
        content.writeBytes(algorithm);
        content.writeBytes(octets);
        return der(0x30, content.toByteArray());
    }

    /** DER 태그 + 길이 + 내용 */
    private static byte[] der(int tag, byte[] content) {
        var out = new ByteArrayOutputStream();
        out.write(tag);
        int length = content.length;
        if (length < 0x80) {
            out.write(length);
        } else {
            int bytes = (Integer.SIZE - Integer.numberOfLeadingZeros(length) + 7) / 8;
            out.write(0x80 | bytes);
            for (int i = bytes - 1; i >= 0; i--) out.write((length >>> (8 * i)) & 0xff);
        }
        out.writeBytes(content);
        return out.toByteArray();
    }
}
