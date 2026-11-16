package com.logssey.secret.response;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

class SecretExplanationProviderTest {
    private static final JsonMapper JSON = new JsonMapper();
    private static final SecretExplanationContext CONTEXT = new SecretExplanationContext("SCAN", "GITHUB",
            List.of("COLLECTION_SUCCEEDED", "VALIDATION_PARTIAL", "MISSING_SESSION_TOKEN", "RATE_LIMITED"),
            List.of("VIEW_FINDINGS", "CHECK_STATUS"), List.of("GITHUB_PAT"));

    @Test void sendsOnlyTheBoundedVocabularyAndReusesTheSameContext() throws Exception {
        var calls = new AtomicInteger();
        var requestBody = new AtomicReference<String>();
        try (var fixture = fixture(200, response("수집을 마쳤고 인증 확인은 일부 남아 있어요. 필요한 구성과 현재 검사 상태를 확인하세요.",
                CONTEXT.facts(), List.of("CHECK_STATUS")), calls, requestBody)) {
            var provider = fixture.provider();
            var first = provider.explain(CONTEXT);
            var cached = provider.explain(CONTEXT);
            assertThat(first.reasonCode()).isEqualTo("CLAUDE_GENERATED");
            assertThat(first.actionCodes()).containsExactly("CHECK_STATUS");
            assertThat(cached.cached()).isTrue();
            assertThat(cached.providerCalled()).isFalse();
            assertThat(calls).hasValue(1);
            var body = JSON.readTree(requestBody.get());
            var fields = JSON.readTree(body.path("messages").get(0).path("content").asText());
            assertThat(fields.size()).isEqualTo(8);
            assertThat(fields.path("issuer").asText()).isEqualTo("GITHUB");
            assertThat(fields.path("referenceDocumentCodes").get(0).asText()).isEqualTo("GITHUB_PAT");
            assertThat(fields.has("documents")).isFalse();
            assertThat(requestBody.get()).doesNotContain("synthetic-api-key", "repositoryName", "maskedLabel", "caseId", "runId");
        }
    }

    @Test void aSingleFactUsesBasicGuidanceWithoutCallingTheProvider() throws Exception {
        var calls = new AtomicInteger();
        try (var fixture = fixture(200, "unused", calls, new AtomicReference<>())) {
            var simple = new SecretExplanationContext("SCAN", "AWS", List.of("METADATA_ONLY"),
                    List.of("CHECK_STATUS"), List.of());
            var result = fixture.provider().explain(simple);
            assertThat(result.reasonCode()).isEqualTo("BASIC_CONTEXT");
            assertThat(result.providerCalled()).isFalse();
            assertThat(result.summary()).isNull();
            assertThat(calls).hasValue(0);
        }
    }

    @Test void rejectsInjectedFieldsAndUnjustifiedProviderAdvice() throws Exception {
        assertThatThrownBy(() -> new SecretExplanationContext("SCAN", "GITHUB",
                List.of("private-file-content"), List.of(), List.of()))
                .isInstanceOf(IllegalArgumentException.class);

        for (var unsafe : List.of(
                response("만료되었습니다", CONTEXT.facts(), List.of("CHECK_STATUS")),
                response("수집된 문서가 없어 탐지 결과나 발견 위치를 확인하지 못했어요.", CONTEXT.facts(), List.of("CHECK_STATUS")),
                response("curl https://example.com 을 실행하세요", CONTEXT.facts(), List.of("CHECK_STATUS")),
                response("확인하세요", CONTEXT.facts(), List.of("RECORD_ACTION")),
                response("확인하세요", List.of("COLLECTION_SUCCEEDED"), List.of("CHECK_STATUS")))) {
            try (var fixture = fixture(200, unsafe, new AtomicInteger(), new AtomicReference<>())) {
                assertThat(fixture.provider().explain(CONTEXT).reasonCode()).isEqualTo("PROVIDER_INVALID_RESPONSE");
            }
        }
    }

    @Test void rateLimitAndAuthenticationErrorsReturnOnlyAReasonAndBasicGuidance() throws Exception {
        for (int status : List.of(401, 429, 503)) {
            try (var fixture = fixture(status, "synthetic-sensitive-error", new AtomicInteger(), new AtomicReference<>())) {
                var result = fixture.provider().explain(CONTEXT);
                assertThat(result.summary()).isNull();
                assertThat(result.providerCalled()).isTrue();
                assertThat(result.toString()).doesNotContain("synthetic-sensitive-error");
            }
        }
    }

    private static String response(String summary, List<String> facts, List<String> actions) {
        return JSON.writeValueAsString(Map.of("type", "message", "role", "assistant", "stop_reason", "end_turn",
                "content", List.of(Map.of("type", "text", "text", JSON.writeValueAsString(Map.of(
                        "summary", summary, "fact_codes", facts, "action_codes", actions))))));
    }

    private static Fixture fixture(int status, String response, AtomicInteger calls,
                                    AtomicReference<String> body) throws Exception {
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/v1/messages", exchange -> {
            calls.incrementAndGet();
            body.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(status, bytes.length);
            try (var stream = exchange.getResponseBody()) { stream.write(bytes); }
        });
        server.start();
        return new Fixture(server, new ClaudeSecretGuideProvider(true, "synthetic-api-key",
                "http://127.0.0.1:" + server.getAddress().getPort() + "/v1/messages",
                ClaudeSecretGuideProvider.MODEL, "", HttpClient.newHttpClient(), 3000, 6, 300));
    }

    private record Fixture(HttpServer server, ClaudeSecretGuideProvider provider) implements AutoCloseable {
        @Override public void close() { server.stop(0); }
    }
}
