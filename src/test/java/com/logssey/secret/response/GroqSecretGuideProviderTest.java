package com.logssey.secret.response;

import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

class GroqSecretGuideProviderTest {
    private static final SecretGuideContext SAFE_CONTEXT = SecretGuideContext.of("AWS",
            "AWS_ACCESS_KEY_PAIR", "CONFIRMED", "OPEN", "UNCHECKED");

    @Test
    void optInAndKeyAreBothRequired() {
        var url = "http://127.0.0.1:1/openai/v1/chat/completions";
        assertThat(new GroqSecretGuideProvider(false, "test-key", url,
                "openai/gpt-oss-20b", HttpClient.newHttpClient()).selectSteps(SAFE_CONTEXT)).isEmpty();
        assertThat(new GroqSecretGuideProvider(true, "", url,
                "openai/gpt-oss-20b", HttpClient.newHttpClient()).selectSteps(SAFE_CONTEXT)).isEmpty();
    }

    @Test
    void sendsOnlySanitizedEnumsAndParsesStrictJsonCodeSelection() throws Exception {
        AtomicReference<String> requestBody = new AtomicReference<>();
        AtomicReference<String> auth = new AtomicReference<>();
        HttpServer server = server(200, response(List.of("VERIFY_EXPOSURE", "EXTERNAL_ROTATION",
                "RECORD_ACTION", "REVALIDATE")), requestBody, auth);
        try {
            var provider = provider(server);
            var context = SecretGuideContext.of("AWS", "ghp_SUPER_SECRET repo/private.env",
                    "CONFIRMED", "OPEN", "UNCHECKED");

            assertThat(provider.selectSteps(context)).contains(List.of("VERIFY_EXPOSURE",
                    "EXTERNAL_ROTATION", "RECORD_ACTION", "REVALIDATE"));
            assertThat(auth.get()).isEqualTo("Bearer test-key");
            var json = new JsonMapper();
            var outbound = json.readTree(requestBody.get());
            var sentFields = json.readTree(outbound.path("messages").get(1).path("content").asText());
            assertThat(sentFields.size()).isEqualTo(5);
            assertThat(sentFields.path("issuer").asText()).isEqualTo("AWS");
            assertThat(sentFields.path("credentialType").asText()).isEqualTo("OTHER");
            assertThat(outbound.path("response_format").path("json_schema")
                    .path("strict").asBoolean()).isTrue();
            assertThat(requestBody.get()).doesNotContain("ghp_SUPER_SECRET", "private.env",
                    "maskedLabel", "sourceObjectRef", "fingerprint", "reasonCode");
        } finally {
            server.stop(0);
        }
    }

    @Test
    void rateLimitMalformedAndOversizeResponsesFallBack() throws Exception {
        for (var scenario : List.of(new Scenario(429, "provider says secret"),
                new Scenario(200, "not-json"), new Scenario(200, "x".repeat(9_000)))) {
            HttpServer server = server(scenario.status(), scenario.body(),
                    new AtomicReference<>(), new AtomicReference<>());
            try {
                assertThat(provider(server).selectSteps(SAFE_CONTEXT)).isEmpty();
            } finally {
                server.stop(0);
            }
        }
    }

    @Test
    void rejectsNonHttpsNonLoopbackEndpointBeforeAnyRequest() {
        var provider = new GroqSecretGuideProvider(true, "test-key",
                "http://example.com/openai/v1/chat/completions", "openai/gpt-oss-20b",
                HttpClient.newHttpClient());
        assertThat(provider.selectSteps(SAFE_CONTEXT)).isEmpty();
    }

    private static GroqSecretGuideProvider provider(HttpServer server) {
        return new GroqSecretGuideProvider(true, "test-key",
                "http://127.0.0.1:" + server.getAddress().getPort() + "/openai/v1/chat/completions",
                "openai/gpt-oss-20b", HttpClient.newHttpClient());
    }

    private static HttpServer server(int status, String body, AtomicReference<String> requestBody,
                                     AtomicReference<String> auth) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/openai/v1/chat/completions", exchange -> {
            requestBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            auth.set(exchange.getRequestHeaders().getFirst("Authorization"));
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        return server;
    }

    private static String response(List<String> codes) {
        var json = new JsonMapper();
        return json.writeValueAsString(Map.of("choices", List.of(Map.of("message", Map.of(
                "content", json.writeValueAsString(Map.of("step_codes", codes)))))));
    }

    private record Scenario(int status, String body) {
    }
}
