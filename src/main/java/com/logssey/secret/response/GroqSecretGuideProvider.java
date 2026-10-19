package com.logssey.secret.response;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Optional GroqCloud Free adapter. Errors and provider bodies are never logged or returned. */
@Component
class GroqSecretGuideProvider implements SecretGuideProvider {
    private static final int MAX_RESPONSE_BYTES = 8_192;
    private static final int MAX_CONTENT_CHARS = 2_048;
    private static final String SYSTEM_PROMPT = """
            Choose general secret-response guide step codes using only the supplied enum values.
            Do not infer validity, severity, compromise, or completion. Do not add prose.
            Begin with VERIFY_EXPOSURE, end with REVALIDATE, and put EXTERNAL_ROTATION before RECORD_ACTION.
            Include each required code exactly once: VERIFY_EXPOSURE, EXTERNAL_ROTATION, RECORD_ACTION, REVALIDATE.
            Optionally include REVIEW_USAGE and REVIEW_PERMISSIONS. Return only the requested JSON object.
            """;

    private final boolean enabled;
    private final String apiKey;
    private final String url;
    private final String model;
    private final HttpClient http;
    private final JsonMapper json = new JsonMapper();

    @Autowired
    GroqSecretGuideProvider(@Value("${logssey.secret.guide.groq.enabled:false}") boolean enabled,
                            @Value("${logssey.secret.guide.groq.api-key:}") String apiKey,
                            @Value("${logssey.secret.guide.groq.url:https://api.groq.com/openai/v1/chat/completions}") String url,
                            @Value("${logssey.secret.guide.groq.model:openai/gpt-oss-20b}") String model) {
        this(enabled, apiKey, url, model, HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NEVER).build());
    }

    GroqSecretGuideProvider(boolean enabled, String apiKey, String url, String model, HttpClient http) {
        this.enabled = enabled;
        this.apiKey = apiKey;
        this.url = url;
        this.model = model;
        this.http = http;
    }

    @Override
    public Optional<List<String>> selectSteps(SecretGuideContext context) {
        if (!enabled || apiKey == null || apiKey.isBlank() || context == null) return Optional.empty();
        URI endpoint;
        try {
            endpoint = URI.create(url);
        } catch (RuntimeException invalidUrl) {
            return Optional.empty();
        }
        if (!allowedEndpoint(endpoint)) return Optional.empty();
        try {
            String body = requestBody(context);
            HttpRequest request = HttpRequest.newBuilder(endpoint)
                    .timeout(Duration.ofSeconds(8))
                    .header("Authorization", "Bearer " + apiKey)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)).build();
            HttpResponse<InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream stream = response.body()) {
                if (response.statusCode() != 200
                        || response.headers().firstValueAsLong("Content-Length")
                        .orElse(0) > MAX_RESPONSE_BYTES) return Optional.empty();
                byte[] bytes = stream.readNBytes(MAX_RESPONSE_BYTES + 1);
                if (bytes.length > MAX_RESPONSE_BYTES) return Optional.empty();
                JsonNode content = json.readTree(bytes).path("choices").path(0)
                        .path("message").path("content");
                if (!content.isTextual() || content.asText().length() > MAX_CONTENT_CHARS) {
                    return Optional.empty();
                }
                JsonNode codes = json.readTree(content.asText()).path("step_codes");
                if (!codes.isArray() || codes.size() < 4 || codes.size() > 6) return Optional.empty();
                List<String> selected = new ArrayList<>(codes.size());
                for (JsonNode code : codes) {
                    if (!code.isTextual()) return Optional.empty();
                    selected.add(code.asText());
                }
                return Optional.of(List.copyOf(selected));
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return Optional.empty();
        } catch (IOException | RuntimeException ignored) {
            // Do not log keys, prompt content, or provider response bodies.
            return Optional.empty();
        }
    }

    private String requestBody(SecretGuideContext context) {
        var schema = Map.of("type", "object", "properties", Map.of("step_codes", Map.of(
                "type", "array", "items", Map.of("type", "string", "enum", SecretGuideCatalog.stepCodes()))),
                "required", List.of("step_codes"), "additionalProperties", false);
        return json.writeValueAsString(Map.of(
                "model", model,
                "max_completion_tokens", 512,
                "messages", List.of(Map.of("role", "system", "content", SYSTEM_PROMPT),
                        Map.of("role", "user", "content", json.writeValueAsString(context.externalFields()))),
                "response_format", Map.of("type", "json_schema", "json_schema", Map.of(
                        "name", "secret_response_steps", "strict", true, "schema", schema))));
    }

    private static boolean allowedEndpoint(URI endpoint) {
        if (endpoint.getHost() == null || endpoint.getRawUserInfo() != null
                || endpoint.getFragment() != null) return false;
        if ("https".equalsIgnoreCase(endpoint.getScheme())) return true;
        // A loopback-only HTTP exception permits isolated local adapter tests.
        return "http".equalsIgnoreCase(endpoint.getScheme())
                && ("127.0.0.1".equals(endpoint.getHost()) || "localhost".equals(endpoint.getHost()));
    }
}
