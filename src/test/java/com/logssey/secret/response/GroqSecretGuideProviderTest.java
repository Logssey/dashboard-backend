package com.logssey.secret.response;

import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

class GroqSecretGuideProviderTest {
    private static final List<String> VALID_CODES = List.of("VERIFY_EXPOSURE", "EXTERNAL_ROTATION", "RECORD_ACTION", "REVALIDATE");
    private static final String MODEL = "openai/gpt-oss-20b";
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
            assertThat(outbound.path("max_completion_tokens").asInt()).isEqualTo(512);
            assertThat(outbound.path("reasoning_effort").asText()).isEqualTo("low");
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

    @Test
    void runtimeAllowsOnlyExactOfficialEndpointAndModelWithoutDisclosingConfiguration() {
        for (String url : List.of("https://example.com/openai/v1/chat/completions",
                "https://api.groq.com.evil.test/openai/v1/chat/completions",
                "https://api.groq.com/elsewhere", "https://api.groq.com:8443/openai/v1/chat/completions",
                "https://api.groq.com/openai/v1/chat/completions?forward=elsewhere",
                "https://user@api.groq.com/openai/v1/chat/completions",
                "https://api.groq.com/openai/v1/chat/completions#fragment",
                "http://127.0.0.1:1/openai/v1/chat/completions", "not a URI")) {
            var provider = new GroqSecretGuideProvider(true, "test-key", url, MODEL, 5000, 6, 300);
            assertThat(provider.configurationReason()).isEqualTo("ENDPOINT_NOT_ALLOWED");
            assertThat(provider.select(SAFE_CONTEXT).providerCalled()).isFalse();
        }
        String official = "https://api.groq.com/openai/v1/chat/completions";
        assertThat(new GroqSecretGuideProvider(true, "test-key", official, MODEL, 5000, 6, 300)
                .configurationReason()).isEqualTo("READY");
        assertThat(new GroqSecretGuideProvider(true, "test-key", official, "other-model", 5000, 6, 300)
                .configurationReason()).isEqualTo("MODEL_NOT_ALLOWED");
        assertThat(new GroqSecretGuideProvider(true, "test-key", official, MODEL, 9000, 6, 300)
                .configurationReason()).isEqualTo("CONFIGURATION_INVALID");
        assertThat(new GroqSecretGuideProvider(true, "test-key\r\nX: injected", official, MODEL, 5000, 6, 300)
                .configurationReason()).isEqualTo("KEY_INVALID");
    }

    @Test
    void returnsPreciseProviderFailuresAndRejectsUnsafeSelections() throws Exception {
        for (var scenario : List.of(new FailureScenario(401, "sensitive provider body", "PROVIDER_REJECTED"),
                new FailureScenario(429, "sensitive provider body", "PROVIDER_RATE_LIMITED"),
                new FailureScenario(503, "sensitive provider body", "PROVIDER_UNAVAILABLE"),
                new FailureScenario(302, "redirect", "PROVIDER_UNAVAILABLE"),
                new FailureScenario(200, "not-json", "PROVIDER_INVALID_RESPONSE"),
                new FailureScenario(200, response(List.of("VERIFY_EXPOSURE", "DELETE_EVERYTHING", "RECORD_ACTION", "REVALIDATE")), "PROVIDER_INVALID_RESPONSE"),
                new FailureScenario(200, response(List.of("VERIFY_EXPOSURE", "RECORD_ACTION", "EXTERNAL_ROTATION", "REVALIDATE")), "PROVIDER_INVALID_RESPONSE"),
                new FailureScenario(200, response(VALID_CODES).replace("\"stop\"", "\"length\""), "PROVIDER_INVALID_RESPONSE"),
                new FailureScenario(200, response(VALID_CODES).replace("\"message\":{", "\"message\":{\"refusal\":\"refused\","), "PROVIDER_INVALID_RESPONSE"),
                new FailureScenario(200, "x".repeat(9_000), "PROVIDER_RESPONSE_TOO_LARGE"))) {
            HttpServer server = server(scenario.status(), scenario.body(), new AtomicReference<>(), new AtomicReference<>());
            try {
                var result = provider(server).select(SAFE_CONTEXT);
                assertThat(result.codes()).isNull();
                assertThat(result.reasonCode()).isEqualTo(scenario.reason());
                assertThat(result.providerCalled()).isTrue();
                assertThat(result.toString()).doesNotContain("sensitive provider body");
            } finally { server.stop(0); }
        }
    }

    @Test
    void limitsChunkedResponseBytesWithoutTrustingContentLength() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/openai/v1/chat/completions", exchange -> {
            exchange.getRequestBody().readAllBytes();
            exchange.sendResponseHeaders(200, 0);
            try { exchange.getResponseBody().write("x".repeat(9_000).getBytes(StandardCharsets.UTF_8)); }
            finally { exchange.close(); }
        });
        server.start();
        try {
            assertThat(provider(server).select(SAFE_CONTEXT).reasonCode()).isEqualTo("PROVIDER_RESPONSE_TOO_LARGE");
        } finally { server.stop(0); }
    }

    @Test
    void wholeResponseDeadlineAlsoCoversAStalledBody() throws Exception {
        for (boolean sendHeaders : List.of(false, true)) {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            CountDownLatch finished = new CountDownLatch(1);
            try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
                server.setExecutor(executor);
                server.createContext("/openai/v1/chat/completions", exchange -> {
                    exchange.getRequestBody().readAllBytes();
                    if (sendHeaders) {
                        exchange.sendResponseHeaders(200, 0);
                        exchange.getResponseBody().write('{');
                        exchange.getResponseBody().flush();
                    }
                    try { finished.await(2, TimeUnit.SECONDS); }
                    catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
                    finally { exchange.close(); }
                });
                server.start();
                var provider = new GroqSecretGuideProvider(true, "test-key", url(server), MODEL,
                        HttpClient.newHttpClient(), 250, 6, 300, true);
                long started = System.nanoTime();
                var result = provider.select(SAFE_CONTEXT);
                assertThat(result.reasonCode()).isEqualTo("PROVIDER_TIMEOUT");
                assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(2));
                finished.countDown();
                server.stop(0);
            } finally { finished.countDown(); server.stop(0); }
        }
    }

    @Test
    void cachesSuccessAndBoundsGlobalCallBudgetAcrossDifferentContexts() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/openai/v1/chat/completions", exchange -> {
            calls.incrementAndGet();
            exchange.getRequestBody().readAllBytes();
            byte[] body = response(VALID_CODES).getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
        try {
            var provider = new GroqSecretGuideProvider(true, "test-key", url(server), MODEL,
                    HttpClient.newHttpClient(), 1000, 1, 300, true);
            assertThat(provider.select(SAFE_CONTEXT).reasonCode()).isEqualTo("GROQ_GENERATED");
            var cached = provider.select(SAFE_CONTEXT);
            assertThat(cached.reasonCode()).isEqualTo("CACHE_HIT");
            assertThat(cached.cached()).isTrue();
            assertThat(cached.providerCalled()).isFalse();
            var otherContext = SecretGuideContext.of("AWS", "AWS_ACCESS_KEY_PAIR", "CONFIRMED", "IN_PROGRESS", "UNCHECKED");
            assertThat(provider.select(otherContext).reasonCode()).isEqualTo("CALL_BUDGET_EXHAUSTED");
            assertThat(calls.get()).isEqualTo(1);
        } finally { server.stop(0); }
    }

    @Test
    void concurrentRequestsDoNotCreateDuplicateProviderCallsAndFailuresHaveCooldown() throws Exception {
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicInteger calls = new AtomicInteger();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            server.setExecutor(executor);
            server.createContext("/openai/v1/chat/completions", exchange -> {
                calls.incrementAndGet();
                exchange.getRequestBody().readAllBytes();
                entered.countDown();
                try { release.await(2, TimeUnit.SECONDS); }
                catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
                exchange.sendResponseHeaders(429, -1);
                exchange.close();
            });
            server.start();
            var provider = provider(server);
            var first = CompletableFuture.supplyAsync(() -> provider.select(SAFE_CONTEXT), executor);
            assertThat(entered.await(2, TimeUnit.SECONDS)).isTrue();
            var concurrent = provider.select(SAFE_CONTEXT);
            assertThat(concurrent.reasonCode()).isEqualTo("REQUEST_IN_PROGRESS");
            assertThat(concurrent.providerCalled()).isFalse();
            release.countDown();
            assertThat(first.get(2, TimeUnit.SECONDS).reasonCode()).isEqualTo("PROVIDER_RATE_LIMITED");
            var retry = provider.select(SAFE_CONTEXT);
            assertThat(retry.reasonCode()).isEqualTo("PROVIDER_RATE_LIMITED");
            assertThat(retry.cached()).isTrue();
            assertThat(retry.providerCalled()).isFalse();
            assertThat(calls.get()).isEqualTo(1);
        } finally { release.countDown(); server.stop(0); }
    }

    private static GroqSecretGuideProvider provider(HttpServer server) {
        return new GroqSecretGuideProvider(true, "test-key",
                url(server),
                "openai/gpt-oss-20b", HttpClient.newHttpClient());
    }

    private static String url(HttpServer server) {
        return "http://127.0.0.1:" + server.getAddress().getPort() + "/openai/v1/chat/completions";
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
        return json.writeValueAsString(Map.of("choices", List.of(Map.of("finish_reason", "stop", "message", Map.of(
                "content", json.writeValueAsString(Map.of("step_codes", codes)))))));
    }

    private record Scenario(int status, String body) {
    }
    private record FailureScenario(int status, String body, String reason) { }
}
