package com.logssey.secret.connection;

import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.assertj.core.api.Assertions.assertThat;

class NotionAuthProbeTest {
    private static final String PAGE = "0123456789abcdef0123456789abcdef";
    // Obviously fake, generated in the test; never a real integration token.
    private static final String FAKE_TOKEN = "ntn_" + "test".repeat(12);
    @TempDir Path temp;

    @Test
    void readsOnlyApprovedPageMetadataWithReadOnlyTokenAndReportsConnected() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        AtomicReference<String> path = new AtomicReference<>();
        AtomicReference<String> auth = new AtomicReference<>();
        HttpServer server = server(200, requests, path, auth);
        try {
            var probe = probe(server, token());
            var result = probe.probe(scope("notion://pages/01234567-89ab-cdef-0123-456789abcdef"));
            assertThat(result).isEqualTo(ConnectionProbeResult.connected());
            assertThat(requests.get()).isEqualTo(1);
            assertThat(path.get()).isEqualTo("/v1/pages/" + PAGE);
            assertThat(auth.get()).isEqualTo("Bearer " + FAKE_TOKEN);
            assertThat(result.toString()).doesNotContain(FAKE_TOKEN, PAGE);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void mapsProviderAnswersToSafeCodes() throws Exception {
        for (int status : new int[]{401, 403, 404}) {
            assertThat(answer(status)).isEqualTo(ConnectionProbeResult.failed("NOTION_ACCESS_DENIED"));
        }
        assertThat(answer(429)).isEqualTo(ConnectionProbeResult.unavailable("NOTION_RATE_LIMITED"));
        assertThat(answer(502)).isEqualTo(ConnectionProbeResult.unavailable("NOTION_UNAVAILABLE"));
    }

    @Test
    void invalidScopeOrMissingTokenNeverMakesANetworkRequest() throws Exception {
        AtomicInteger requests = new AtomicInteger();
        HttpServer server = server(200, requests, new AtomicReference<>(), new AtomicReference<>());
        try {
            var withToken = probe(server, token());
            assertThat(withToken.probe(scope("notion://workspace/all")))
                    .isEqualTo(ConnectionProbeResult.failed("INVALID_APPROVED_SCOPE"));
            assertThat(withToken.probe(new SecretConnectionTestRepository.Scope(
                    "NOTION_PAGE_CONTENT", "notion://pages/" + PAGE, "ALL_HISTORY")))
                    .isEqualTo(ConnectionProbeResult.failed("INVALID_APPROVED_SCOPE"));
            assertThat(probe(server, "").probe(scope("notion://pages/" + PAGE)))
                    .isEqualTo(ConnectionProbeResult.unavailable("NOTION_TOKEN_UNAVAILABLE"));
            Path wrong = Files.writeString(temp.resolve("wrong"), "not-a-notion-token");
            assertThat(probe(server, wrong.toString()).probe(scope("notion://pages/" + PAGE)))
                    .isEqualTo(ConnectionProbeResult.unavailable("NOTION_TOKEN_UNAVAILABLE"));
            assertThat(requests.get()).isZero();
        } finally {
            server.stop(0);
        }
    }

    private ConnectionProbeResult answer(int status) throws Exception {
        HttpServer server = server(status, new AtomicInteger(), new AtomicReference<>(), new AtomicReference<>());
        try {
            return probe(server, token()).probe(scope("notion://pages/" + PAGE));
        } finally {
            server.stop(0);
        }
    }

    private String token() throws Exception {
        return Files.writeString(temp.resolve("notion-token"), FAKE_TOKEN + "\n").toString();
    }

    private static NotionAuthProbe probe(HttpServer server, String tokenPath) {
        return new NotionAuthProbe(tokenPath,
                URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/"),
                HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build());
    }

    private static HttpServer server(int status, AtomicInteger requests, AtomicReference<String> path,
                                     AtomicReference<String> auth) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            requests.incrementAndGet();
            path.set(exchange.getRequestURI().getPath());
            auth.set(exchange.getRequestHeaders().getFirst("Authorization"));
            byte[] body = "{\"object\":\"page\"}".getBytes();
            exchange.sendResponseHeaders(status, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        return server;
    }

    private static SecretConnectionTestRepository.Scope scope(String ref) {
        return new SecretConnectionTestRepository.Scope("NOTION_PAGE_CONTENT", ref, "CURRENT_VERSION_ONLY");
    }
}
