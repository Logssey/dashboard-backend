package com.logssey.secret.connection;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.time.Clock;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.assertj.core.api.Assertions.assertThat;

class GitHubAuthProbeTest {
    @TempDir Path temp;

    @Test
    void asksOnlyForReadTokenScopedToApprovedRepository() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        AtomicReference<String> body = new AtomicReference<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/app/installations/17/access_tokens", exchange -> {
            requests.incrementAndGet();
            body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] response = """
                    {"token":"ephemeral-token","repositories":[{"full_name":"Logssey/test-find-key"}],
                    "permissions":{"contents":"read"}}
                    """.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(201, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.start();
        try {
            Path key = privateKey();
            var probe = new GitHubAuthProbe(15, 17, key.toString(),
                    URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/"),
                    HttpClient.newHttpClient(), Clock.systemUTC());
            var result = probe.probe(scope("github://Logssey/test-find-key/develop/fixtures/"));

            assertThat(result).isEqualTo(ConnectionProbeResult.connected());
            assertThat(requests.get()).isEqualTo(1);
            assertThat(body.get()).contains("\"repositories\":[\"test-find-key\"]")
                    .contains("\"contents\":\"read\"")
                    .doesNotContain("ephemeral-token");
        } finally {
            server.stop(0);
        }
    }

    @Test
    void invalidScopeAndMissingAppCannotMakeNetworkRequest() {
        var probe = new GitHubAuthProbe(0, 0, "", URI.create("http://127.0.0.1:1/"),
                HttpClient.newHttpClient(), Clock.systemUTC());
        assertThat(probe.probe(scope("github://Logssey/test-find-key/develop/fixtures/")))
                .isEqualTo(ConnectionProbeResult.unavailable("GITHUB_APP_UNAVAILABLE"));
        assertThat(probe.probe(scope("github://evil.example/a/branch/dir/?x=1")))
                .isEqualTo(ConnectionProbeResult.failed("INVALID_APPROVED_SCOPE"));
    }

    @Test
    void rejectsTokenThatIsNotLimitedToTheExactReadOnlyRepository() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/app/installations/17/access_tokens", exchange -> {
            byte[] response = """
                    {"token":"ephemeral-token","repositories":[{"full_name":"Logssey/other-repo"}],
                    "permissions":{"contents":"write"}}
                    """.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(201, response.length);
            exchange.getResponseBody().write(response);
            exchange.close();
        });
        server.start();
        try {
            var probe = new GitHubAuthProbe(15, 17, privateKey().toString(),
                    URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/"),
                    HttpClient.newHttpClient(), Clock.systemUTC());
            assertThat(probe.probe(scope("github://Logssey/test-find-key/develop/fixtures/")))
                    .isEqualTo(ConnectionProbeResult.failed("GITHUB_ACCESS_DENIED"));
        } finally {
            server.stop(0);
        }
    }

    private Path privateKey() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        byte[] pkcs8 = generator.generateKeyPair().getPrivate().getEncoded();
        Path file = temp.resolve("app.pem");
        Files.writeString(file, "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(pkcs8)
                + "\n-----END PRIVATE KEY-----\n", StandardCharsets.US_ASCII);
        java.util.Arrays.fill(pkcs8, (byte) 0);
        return file;
    }

    private static SecretConnectionTestRepository.Scope scope(String ref) {
        return new SecretConnectionTestRepository.Scope(
                "GITHUB_REPOSITORY_FILES", ref, "CURRENT_COMMIT_ONLY");
    }
}
