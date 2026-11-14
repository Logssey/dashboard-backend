package com.logssey.secret.response;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.json.JsonMapper;

class ClaudeSecretGuideProviderTest {
    private static final List<String> CODES = List.of("VERIFY_EXPOSURE", "EXTERNAL_ROTATION", "RECORD_ACTION", "REVALIDATE");
    private static final SecretGuideContext CONTEXT = SecretGuideContext.of("GITHUB", "GITHUB_CLASSIC_PAT", "CONFIRMED", "OPEN", "INVALID");
    private static final JsonMapper JSON = new JsonMapper();

    @Test void currentMessagesContractUsesOnlyEnumsAndRetainsOriginalGenerationTimeOnCacheHits() throws Exception {
        try (var fixture = server(200, response(CODES))) {
            var provider = provider(fixture);
            var context = SecretGuideContext.of("GITHUB", "ghp_private repo/secret.env", "CONFIRMED", "OPEN", "INVALID");
            var first = provider.select(context);
            var cached = provider.select(context);
            assertThat(first.codes()).isEqualTo(CODES);
            assertThat(first.reasonCode()).isEqualTo("CLAUDE_GENERATED");
            assertThat(first.generatedAt()).isNotNull();
            assertThat(cached.generatedAt()).isEqualTo(first.generatedAt());
            assertThat(cached.cached()).isTrue();
            assertThat(cached.providerCalled()).isFalse();
            assertThat(fixture.calls()).hasValue(1);
            assertThat(fixture.auth().get()).isEqualTo("Bearer test-key");
            assertThat(fixture.version().get()).isEqualTo("2026-10-21");
            assertThat(fixture.workspace().get()).isEqualTo("wrkspc_TestWorkspace");
            var body = JSON.readTree(fixture.body().get());
            var safe = JSON.readTree(body.path("messages").get(0).path("content").asText());
            assertThat(safe.size()).isEqualTo(5);
            assertThat(safe.path("credentialType").asText()).isEqualTo("OTHER");
            assertThat(safe.path("validationStatus").asText()).isEqualTo("INVALID");
            assertThat(body.path("model").asText()).isEqualTo(ClaudeSecretGuideProvider.MODEL);
            assertThat(body.path("max_tokens").asInt()).isEqualTo(768);
            assertThat(body.path("thinking").path("type").asText()).isEqualTo("between_tools");
            assertThat(body.path("output_config").path("effort").asText()).isEqualTo("low");
            assertThat(body.path("output_config").path("format").path("type").asText()).isEqualTo("json_schema");
            assertThat(fixture.body().get()).doesNotContain("ghp_private", "secret.env", "maskedLabel",
                    "sourceObjectRef", "fingerprint", "caseId", "temperature", "maxItems", "minItems");
        }
    }

    @Test void refusesUnsafeDestinationsKeysWorkspaceModelsAndUnavailableFilesBeforeSending(@TempDir Path directory) throws Exception {
        for (String endpoint : List.of("https://example.com/v1/messages", "https://api.anthropic.com.evil.test/v1/messages",
                "https://api.anthropic.com:8443/v1/messages", "https://api.anthropic.com/v1/messages?forward=elsewhere",
                "https://user@api.anthropic.com/v1/messages", "https://api.anthropic.com/v1/messages#part",
                "http://127.0.0.1:1/v1/messages", "not a URI")) {
            var provider = runtime(true, "test-key", "", endpoint, ClaudeSecretGuideProvider.MODEL, "");
            assertThat(provider.configurationReason()).isEqualTo("ENDPOINT_NOT_ALLOWED");
            assertThat(provider.select(CONTEXT).providerCalled()).isFalse();
        }
        String official = "https://api.anthropic.com/v1/messages";
        assertThat(runtime(false, "test-key", "", official, ClaudeSecretGuideProvider.MODEL, "").configurationReason()).isEqualTo("DISABLED");
        assertThat(runtime(true, "", "", official, ClaudeSecretGuideProvider.MODEL, "").configurationReason()).isEqualTo("KEY_MISSING");
        assertThat(runtime(true, "bad\r\nheader", "", official, ClaudeSecretGuideProvider.MODEL, "").configurationReason()).isEqualTo("KEY_INVALID");
        assertThat(runtime(true, "test-key", "", official, "arbitrary-model", "").configurationReason()).isEqualTo("MODEL_NOT_ALLOWED");
        assertThat(runtime(true, "test-key", "", official, ClaudeSecretGuideProvider.MODEL, "bad workspace").configurationReason()).isEqualTo("WORKSPACE_INVALID");
        assertThat(runtime(true, "", directory.resolve("missing.token").toString(), official, ClaudeSecretGuideProvider.MODEL, "").configurationReason()).isEqualTo("KEY_FILE_UNREADABLE");
        Path file = directory.resolve("synthetic-key.token");
        Files.writeString(file, "test-only-key\n");
        assertThat(runtime(true, "", file.toString(), official, ClaudeSecretGuideProvider.MODEL, "").configurationReason()).isEqualTo("READY");
        Files.writeString(file, "\uFEFFtest-only-key\n");
        assertThat(runtime(true, "", file.toString(), official, ClaudeSecretGuideProvider.MODEL, "").configurationReason()).isEqualTo("READY");
        Files.writeString(file, "x".repeat(4097));
        assertThat(runtime(true, "", file.toString(), official, ClaudeSecretGuideProvider.MODEL, "").configurationReason()).isEqualTo("KEY_FILE_UNREADABLE");
    }

    @Test void failureBodiesAndUnsafeModelResponsesNeverEnterTheGuide() throws Exception {
        for (var scenario : List.of(new Scenario(401, "private provider body", "PROVIDER_AUTHENTICATION_FAILED"),
                new Scenario(403, "private provider body", "PROVIDER_ACCESS_DENIED"),
                new Scenario(402, "private provider body", "PROVIDER_BILLING_REQUIRED"),
                new Scenario(400, "private provider body", "PROVIDER_REJECTED"),
                new Scenario(429, "private provider body", "PROVIDER_RATE_LIMITED"),
                new Scenario(503, "private provider body", "PROVIDER_UNAVAILABLE"),
                new Scenario(302, "redirect", "PROVIDER_UNAVAILABLE"),
                new Scenario(200, "not-json", "PROVIDER_INVALID_RESPONSE"),
                new Scenario(200, "x".repeat(9000), "PROVIDER_RESPONSE_TOO_LARGE"),
                new Scenario(200, response(List.of("VERIFY_EXPOSURE", "DELETE_ALL", "RECORD_ACTION", "REVALIDATE")), "PROVIDER_INVALID_RESPONSE"),
                new Scenario(200, response(CODES).replace("end_turn", "max_tokens"), "PROVIDER_INVALID_RESPONSE"),
                new Scenario(200, response(CODES).replace("\"role\":\"assistant\"", "\"role\":\"assistant\",\"stop_details\":{\"type\":\"refusal\"}"), "PROVIDER_INVALID_RESPONSE"))) {
            try (var fixture = server(scenario.http(), scenario.body())) {
                var result = provider(fixture).select(CONTEXT);
                assertThat(result.reasonCode()).isEqualTo(scenario.reason());
                assertThat(result.codes()).isNull();
                assertThat(result.generatedAt()).isNull();
                assertThat(result.providerCalled()).isTrue();
                assertThat(result.toString()).doesNotContain("private provider body");
            }
        }
    }

    @Test void sharedBudgetDenialNeverSendsHttpAndDoesNotProduceAGeneration() throws Exception {
        try (var fixture = server(200, response(CODES))) {
            var budget = mock(SecretAiCallBudget.class);
            var permit = mock(SecretAiCallBudget.Permit.class);
            when(budget.acquire(eq("CLAUDE"), eq(ClaudeSecretGuideProvider.MODEL), eq("GUIDE"), any())).thenReturn(permit);
            when(permit.reasonCode()).thenReturn("CALL_BUDGET_UNAVAILABLE");
            var provider = new ClaudeSecretGuideProvider(true, "test-key", fixture.url(), ClaudeSecretGuideProvider.MODEL,
                    "", HttpClient.newHttpClient(), 5000, 6, 300, budget);
            var result = provider.select(CONTEXT);
            assertThat(result.reasonCode()).isEqualTo("CALL_BUDGET_UNAVAILABLE");
            assertThat(result.providerCalled()).isFalse();
            assertThat(fixture.calls()).hasValue(0);
            verify(permit).close();
        }
    }

    @Test void cacheHitsAvoidAdditionalSharedBudgetReservations() throws Exception {
        try (var fixture = server(200, response(CODES))) {
            var budget = mock(SecretAiCallBudget.class);
            var permit = mock(SecretAiCallBudget.Permit.class);
            when(budget.acquire(eq("CLAUDE"), eq(ClaudeSecretGuideProvider.MODEL), eq("GUIDE"), any())).thenReturn(permit);
            when(permit.allowed()).thenReturn(true);
            var provider = new ClaudeSecretGuideProvider(true, "test-key", fixture.url(), ClaudeSecretGuideProvider.MODEL,
                    "", HttpClient.newHttpClient(), 5000, 6, 300, budget);
            assertThat(provider.select(CONTEXT).codes()).isEqualTo(CODES);
            assertThat(provider.select(CONTEXT).cached()).isTrue();
            verify(budget, times(1)).acquire(eq("CLAUDE"), eq(ClaudeSecretGuideProvider.MODEL), eq("GUIDE"), any());
            verify(permit, times(1)).close();
            assertThat(fixture.calls()).hasValue(1);
        }
    }

    @Test void singleFlightAndLocalBudgetBoundRequestsAcrossDifferentEnumContexts() throws Exception {
        var started = new CountDownLatch(1);
        var release = new CountDownLatch(1);
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        var calls = new AtomicInteger();
        server.createContext("/v1/messages", exchange -> {
            calls.incrementAndGet(); started.countDown();
            try { release.await(5, TimeUnit.SECONDS); } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
            byte[] bytes = response(CODES).getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes); exchange.close();
        });
        server.start();
        try {
            String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/v1/messages";
            var provider = new ClaudeSecretGuideProvider(true, "test-key", url, ClaudeSecretGuideProvider.MODEL, "", HttpClient.newHttpClient(), 5000, 1, 300);
            var first = CompletableFuture.supplyAsync(() -> provider.select(CONTEXT));
            assertThat(started.await(3, TimeUnit.SECONDS)).isTrue();
            assertThat(provider.select(CONTEXT).reasonCode()).isEqualTo("REQUEST_IN_PROGRESS");
            release.countDown();
            assertThat(first.get(5, TimeUnit.SECONDS).codes()).isEqualTo(CODES);
            assertThat(provider.select(CONTEXT).cached()).isTrue();
            var other = SecretGuideContext.of("NOTION", "NOTION_CONNECTION_TOKEN", "CONFIRMED", "OPEN", "UNCHECKED");
            assertThat(provider.select(other).reasonCode()).isEqualTo("CALL_BUDGET_EXHAUSTED");
            assertThat(calls).hasValue(1);
        } finally { release.countDown(); server.stop(0); }
    }

    @Test void delayedResponseBodiesShareTheRequestDeadline() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        var release = new CountDownLatch(1);
        server.createContext("/v1/messages", exchange -> {
            exchange.sendResponseHeaders(200, 0);
            exchange.getResponseBody().write('{'); exchange.getResponseBody().flush();
            try { release.await(2, TimeUnit.SECONDS); } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
            exchange.close();
        });
        server.start();
        try {
            var provider = new ClaudeSecretGuideProvider(true, "test-key", "http://127.0.0.1:" + server.getAddress().getPort() + "/v1/messages",
                    ClaudeSecretGuideProvider.MODEL, "", HttpClient.newHttpClient(), 300, 6, 300);
            long start = System.nanoTime();
            assertThat(provider.select(CONTEXT).reasonCode()).isEqualTo("PROVIDER_TIMEOUT");
            assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(2));
        } finally { release.countDown(); server.stop(0); }
    }

    private static ClaudeSecretGuideProvider runtime(boolean enabled, String key, String file, String url, String model, String workspace) {
        return new ClaudeSecretGuideProvider(enabled, key, file, url, model, workspace, 45000, 6, 300);
    }
    private static ClaudeSecretGuideProvider provider(Fixture fixture) {
        return new ClaudeSecretGuideProvider(true, "test-key", fixture.url(), ClaudeSecretGuideProvider.MODEL,
                "wrkspc_TestWorkspace", HttpClient.newHttpClient(), 5000, 6, 300);
    }
    private static String response(List<String> codes) {
        return JSON.writeValueAsString(Map.of("type", "message", "role", "assistant", "stop_reason", "end_turn",
                "content", List.of(Map.of("type", "text", "text", JSON.writeValueAsString(Map.of("step_codes", codes))))));
    }
    private static Fixture server(int status, String body) throws Exception {
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        var request = new AtomicReference<String>(); var auth = new AtomicReference<String>();
        var version = new AtomicReference<String>(); var workspace = new AtomicReference<String>();
        var calls = new AtomicInteger();
        server.createContext("/v1/messages", exchange -> {
            calls.incrementAndGet();
            request.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            auth.set(exchange.getRequestHeaders().getFirst("Authorization"));
            version.set(exchange.getRequestHeaders().getFirst("anthropic-version"));
            workspace.set(exchange.getRequestHeaders().getFirst("anthropic-workspace-id"));
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length); exchange.getResponseBody().write(bytes); exchange.close();
        });
        server.start();
        return new Fixture(server, "http://127.0.0.1:" + server.getAddress().getPort() + "/v1/messages", request, auth, version, workspace, calls);
    }
    private record Fixture(HttpServer server, String url, AtomicReference<String> body, AtomicReference<String> auth,
                           AtomicReference<String> version, AtomicReference<String> workspace, AtomicInteger calls) implements AutoCloseable {
        @Override public void close() { server.stop(0); }
    }
    private record Scenario(int http, String body, String reason) { }
}
