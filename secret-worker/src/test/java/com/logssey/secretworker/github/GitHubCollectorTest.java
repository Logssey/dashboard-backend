package com.logssey.secretworker.github;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

class GitHubCollectorTest {
    private static final String COMMIT = "b".repeat(40);
    private static final String ROOT = "c".repeat(40);
    private static final String FIXTURES = "d".repeat(40);
    private static final String BLOB = "e".repeat(40);
    private static final String OTHER_BLOB = "f".repeat(40);
    private static final String API = "repos/Logssey/test-find-key/git/";
    private final JsonMapper json = new JsonMapper();
    private HttpServer server;
    private KeyPair key;
    private GitHubRestClient api;
    private GitHubCollector collector;
    private final List<String> requests = new ArrayList<>();
    private String tokenResponse;
    private String fixturesTree;
    private String blobResponse;
    private int blobStatus;
    private final AtomicInteger outsideReads = new AtomicInteger();
    private String capturedJwt;
    private String capturedTokenRequest;

    @Test
    void repositoryVisibilityRequiresTypedConsistentProviderMetadata() {
        var at = java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC);
        for (String value :
                List.of(
                        "{}",
                        "{\"private\":null}",
                        "{\"private\":\"false\"}",
                        "{\"visibility\":false}",
                        "{\"private\":false,\"visibility\":\"invalid\"}",
                        "{\"private\":true,\"visibility\":\"public\"}")) {
            var observation = GitHubCollector.classifyRepositoryAccess(json.readTree(value), at);
            assertThat(observation.publicRepository()).isFalse();
            assertThat(observation.metadataComplete()).isFalse();
        }
        assertThat(
                        GitHubCollector.classifyRepositoryAccess(
                                        json.readTree("{\"private\":false}"), at)
                                .publicRepository())
                .isTrue();
        assertThat(
                        GitHubCollector.classifyRepositoryAccess(
                                        json.readTree("{\"visibility\":\"public\"}"), at)
                                .publicRepository())
                .isTrue();
        var privateRepo =
                GitHubCollector.classifyRepositoryAccess(json.readTree("{\"private\":true}"), at);
        assertThat(privateRepo.publicRepository()).isFalse();
        assertThat(privateRepo.metadataComplete()).isTrue();
    }

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        key = generator.generateKeyPair();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", this::respond);
        server.start();
        api =
                new GitHubRestClient(
                        URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/"),
                        HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build());
        var provider = new GitHubAppTokenProvider(123, 456, key.getPrivate(), api,
                Clock.fixed(Instant.parse("2026-10-14T00:00:00Z"), ZoneOffset.UTC));
        collector = new GitHubCollector(api, provider);
        tokenResponse = json.writeValueAsString(Map.of(
                "token", "test-installation-token",
                "permissions", Map.of("contents", "read"),
                "repositories", List.of(Map.of("full_name", "Logssey/test-find-key"))));
        fixturesTree = tree(FIXTURES, false, List.of(
                entry("one.txt", "blob", "100644", BLOB, 13),
                entry("link", "blob", "120000", OTHER_BLOB, 12),
                entry("huge.txt", "blob", "100644", OTHER_BLOB, 2_000_000)));
        blobResponse = blob(BLOB, "fixture input");
        blobStatus = 200;
    }

    @AfterEach
    void tearDown() {
        server.stop(0);
    }

    @Test
    void scopesAppTokenAndReadsOnlyApprovedPrefixAtPinnedCommit() throws Exception {
        List<GitHubCollector.Source> seen = new ArrayList<>();
        List<byte[]> buffers = new ArrayList<>();
        List<String> values = new ArrayList<>();
        var result = collector.collect(scope(), GitHubCollectionLimits.DEFAULT, (source, content) -> {
            seen.add(source);
            values.add(new String(content, StandardCharsets.UTF_8));
            buffers.add(content);
        });

        assertThat(result.status()).isEqualTo(GitHubCollector.Status.PARTIAL);
        assertThat(result.objectCount()).isEqualTo(1);
        assertThat(result.byteCount()).isEqualTo(13);
        assertThat(seen.get(0).path()).isEqualTo("fixtures/one.txt");
        assertThat(seen.get(0).commitSha()).isEqualTo(COMMIT);
        assertThat(values).containsExactly("fixture input");
        assertThat(buffers.get(0)).containsOnly((byte) 0);
        assertThat(result.gaps()).extracting(GitHubCollector.Gap::code)
                .containsExactlyInAnyOrder(GitHubCollector.GapCode.UNSUPPORTED_OBJECT,
                        GitHubCollector.GapCode.FILE_TOO_LARGE);
        assertThat(requests).contains("GET /" + API + "ref/heads/main",
                "GET /" + API + "commits/" + COMMIT,
                "GET /" + API + "trees/" + ROOT,
                "GET /" + API + "trees/" + FIXTURES,
                "GET /" + API + "blobs/" + BLOB);
        assertThat(outsideReads).hasValue(0);
        assertThat(capturedTokenRequest).contains("\"repositories\":[\"test-find-key\"]")
                .contains("\"contents\":\"read\"");
        assertThat(result.toString()).doesNotContain("fixture input");
        verifyJwt(capturedJwt);
    }

    @Test
    void treatsMissingApprovedDirectoryAsFailureRatherThanEmptySuccess() {
        fixturesTree = tree(FIXTURES, false, List.of());
        var result =
                collector.collect(
                        new GitHubApprovedScope("Logssey", "test-find-key", "main", "absent/"),
                        GitHubCollectionLimits.DEFAULT,
                        (source, bytes) -> {});
        assertThat(result.status()).isEqualTo(GitHubCollector.Status.FAILED);
        assertThat(result.gaps()).extracting(GitHubCollector.Gap::code)
                .containsExactly(GitHubCollector.GapCode.PATH_NOT_FOUND);
        assertThat(outsideReads).hasValue(0);
    }

    @Test
    void reportsPartialFailureWithoutProviderBodyOrBlobContent() {
        fixturesTree = tree(FIXTURES, false, List.of(
                entry("one.txt", "blob", "100644", BLOB, 13),
                entry("two.txt", "blob", "100644", OTHER_BLOB, 13)));
        blobStatus = 403;
        var result = collector.collect(scope(), GitHubCollectionLimits.DEFAULT, (source, bytes) -> { });
        assertThat(result.status()).isEqualTo(GitHubCollector.Status.PARTIAL);
        assertThat(result.objectCount()).isEqualTo(1);
        assertThat(result.gaps()).extracting(GitHubCollector.Gap::code)
                .containsExactly(GitHubCollector.GapCode.ACCESS_DENIED);
        assertThat(result.toString()).doesNotContain("sensitive-error-body", "fixture input");
    }

    @Test
    void rejectsTokenForARepositoryOutsideInstallationScope() {
        tokenResponse = json.writeValueAsString(Map.of("token", "test-installation-token",
                "permissions", Map.of("contents", "read"),
                "repositories", List.of(Map.of("full_name", "other/test-find-key"))));
        var result = collector.collect(scope(), GitHubCollectionLimits.DEFAULT, (source, bytes) -> { });
        assertThat(result.status()).isEqualTo(GitHubCollector.Status.FAILED);
        assertThat(result.gaps()).extracting(GitHubCollector.Gap::code)
                .containsExactly(GitHubCollector.GapCode.ACCESS_DENIED);
        assertThat(requests).hasSize(1);
    }

    @Test
    void rejectsTruncatedTreeAndBinaryFileAsIncompleteCoverage() {
        fixturesTree = tree(FIXTURES, true, List.of(entry("one.txt", "blob", "100644", BLOB, 13)));
        var truncated = collector.collect(scope(), GitHubCollectionLimits.DEFAULT, (source, bytes) -> { });
        assertThat(truncated.status()).isEqualTo(GitHubCollector.Status.FAILED);
        assertThat(truncated.gaps()).extracting(GitHubCollector.Gap::code)
                .containsExactly(GitHubCollector.GapCode.TREE_TRUNCATED);

        fixturesTree = tree(FIXTURES, false, List.of(entry("one.txt", "blob", "100644", BLOB, 3)));
        blobResponse = json.writeValueAsString(Map.of("sha", BLOB, "encoding", "base64", "size", 3,
                "content", Base64.getEncoder().encodeToString(new byte[]{'a', 0, 'b'})));
        var binary = collector.collect(scope(), GitHubCollectionLimits.DEFAULT, (source, bytes) -> { });
        assertThat(binary.status()).isEqualTo(GitHubCollector.Status.FAILED);
        assertThat(binary.gaps()).extracting(GitHubCollector.Gap::code)
                .containsExactly(GitHubCollector.GapCode.BINARY_FILE);
    }

    @Test
    void refusesUnapprovedHistoryAndTraversal() {
        assertThat(GitHubApprovedScope.fromApprovedRef(
                "github://Logssey/test-find-key/main/fixtures/", "CURRENT_COMMIT_ONLY"))
                .isEqualTo(scope());
        assertThatThrownBy(() -> GitHubApprovedScope.fromApprovedRef(
                "github://Logssey/test-find-key/main/fixtures/", "ALL_HISTORY"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> GitHubApprovedScope.fromApprovedRef(
                "github://Logssey/test-find-key/main/fixtures/%2e%2e/", "CURRENT_COMMIT_ONLY"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new GitHubApprovedScope("Logssey", "test-find-key", "main", "../"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void unavailableRepositoryMetadataDoesNotPreventContentCollection() {
        fixturesTree=tree(FIXTURES,false,List.of(entry("one.txt","blob","100644",BLOB,13)));
        var metadata=collector.repositoryAccess(scope());
        assertThat(metadata.metadataComplete()).isFalse();
        assertThat(metadata.publicRepository()).isFalse();
        assertThat(metadata.reasonCode()).isEqualTo("METADATA_UNAVAILABLE");
        assertThat(collector.collect(scope(),GitHubCollectionLimits.DEFAULT,(source,bytes)->{}).status()).isEqualTo(GitHubCollector.Status.SUCCEEDED);
    }

    private GitHubApprovedScope scope() {
        return new GitHubApprovedScope("Logssey", "test-find-key", "main", "fixtures/");
    }

    private void respond(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getRawPath();
        String method = exchange.getRequestMethod();
        requests.add(method + " " + path);
        String response;
        int status = 200;
        if (path.equals("/app/installations/456/access_tokens")) {
            capturedJwt =
                    exchange.getRequestHeaders()
                            .getFirst("Authorization")
                            .substring("Bearer ".length());
            capturedTokenRequest = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            response = tokenResponse;
        } else if (path.equals("/" + API + "ref/heads/main")) {
            response =
                    json.writeValueAsString(
                            Map.of("object", Map.of("type", "commit", "sha", COMMIT)));
        } else if (path.equals("/" + API + "commits/" + COMMIT)) {
            response = json.writeValueAsString(Map.of("tree", Map.of("sha", ROOT)));
        } else if (path.equals("/" + API + "trees/" + ROOT)) {
            response = tree(ROOT, false, List.of(entry("fixtures", "tree", "040000", FIXTURES, 0),
                    entry("outside.txt", "blob", "100644", OTHER_BLOB, 13)));
        } else if (path.equals("/" + API + "trees/" + FIXTURES)) {
            response = fixturesTree;
        } else if (path.equals("/" + API + "blobs/" + BLOB)) {
            response = blobResponse;
        } else if (path.equals("/" + API + "blobs/" + OTHER_BLOB)) {
            status = blobStatus;
            response = status == 200 ? blob(OTHER_BLOB, "fixture input") : "sensitive-error-body";
            if (status == 200) outsideReads.incrementAndGet();
        } else {
            outsideReads.incrementAndGet();
            status = 404;
            response = "unknown route";
        }
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (var output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }

    private String tree(String sha, boolean truncated, List<Map<String, Object>> entries) {
        return json.writeValueAsString(Map.of("sha", sha, "truncated", truncated, "tree", entries));
    }

    private static Map<String, Object> entry(String path, String type, String mode, String sha, long size) {
        return Map.of("path", path, "type", type, "mode", mode, "sha", sha, "size", size);
    }

    private String blob(String sha, String content) {
        return json.writeValueAsString(
                Map.of(
                        "sha",
                        sha,
                        "encoding",
                        "base64",
                        "size",
                        content.getBytes(StandardCharsets.UTF_8).length,
                        "content",
                        Base64.getEncoder()
                                .encodeToString(content.getBytes(StandardCharsets.UTF_8))));
    }

    private void verifyJwt(String jwt) throws Exception {
        String[] parts = jwt.split("\\.");
        assertThat(parts).hasSize(3);
        JsonNode header = json.readTree(Base64.getUrlDecoder().decode(parts[0]));
        JsonNode claims = json.readTree(Base64.getUrlDecoder().decode(parts[1]));
        assertThat(header.path("alg").asText()).isEqualTo("RS256");
        assertThat(claims.path("iss").asLong()).isEqualTo(123);
        assertThat(claims.path("exp").asLong() - claims.path("iat").asLong()).isEqualTo(600);
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(key.getPublic());
        verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertThat(verifier.verify(Base64.getUrlDecoder().decode(parts[2]))).isTrue();
    }
}
