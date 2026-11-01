package com.logssey.secret.response;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Optional Groq adapter. Only catalog codes cross the output boundary; bodies are never logged. */
@Component
class GroqSecretGuideProvider implements SecretGuideProvider {
    private static final int MAX_RESPONSE_BYTES = 8_192;
    private static final int MAX_CONTENT_CHARS = 2_048;
    private static final int MAX_CACHE_ENTRIES = 128;
    private static final String API_PATH = "/openai/v1/chat/completions";
    private static final String MODEL = "openai/gpt-oss-20b";
    private static final long WINDOW_NANOS = Duration.ofMinutes(1).toNanos();
    private static final String SYSTEM_PROMPT = """
            Choose general secret-response guide step codes using only the supplied enum values.
            Do not infer validity, severity, compromise, or completion. Do not add prose.
            Begin with VERIFY_EXPOSURE, end with REVALIDATE, and put EXTERNAL_ROTATION before RECORD_ACTION.
            Include each required code exactly once: VERIFY_EXPOSURE, EXTERNAL_ROTATION, RECORD_ACTION, REVALIDATE.
            Optionally include REVIEW_USAGE and REVIEW_PERMISSIONS. Return only the requested JSON object.
            """;

    private final boolean enabled;
    private final String apiKey;
    private final URI endpoint;
    private final String model;
    private final HttpClient http;
    private final int timeoutMillis;
    private final int callsPerMinute;
    private final long cacheNanos;
    private final boolean configurationValid;
    private final boolean endpointAllowed;
    private final JsonMapper json = new JsonMapper();
    // Cache keys contain only five whitelisted enums, never a case ID, actor, path, or credential.
    private final Map<SecretGuideContext, CachedSelection> cache = new LinkedHashMap<>();
    private long windowStarted = System.nanoTime();
    private int windowCalls;
    private boolean inFlight;

    @Autowired
    GroqSecretGuideProvider(@Value("${logssey.secret.guide.groq.enabled:false}") boolean enabled,
                            @Value("${logssey.secret.guide.groq.api-key:}") String apiKey,
                            @Value("${logssey.secret.guide.groq.url:https://api.groq.com/openai/v1/chat/completions}") String url,
                            @Value("${logssey.secret.guide.groq.model:openai/gpt-oss-20b}") String model,
                            @Value("${logssey.secret.guide.groq.timeout-ms:5000}") int timeoutMillis,
                            @Value("${logssey.secret.guide.groq.calls-per-minute:6}") int callsPerMinute,
                            @Value("${logssey.secret.guide.groq.cache-seconds:300}") int cacheSeconds) {
        this(enabled, apiKey, url, model, HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .followRedirects(HttpClient.Redirect.NEVER).build(),
                timeoutMillis, callsPerMinute, cacheSeconds, false);
    }

    /** Loopback is available only to package-local injected HTTP tests, never runtime configuration. */
    GroqSecretGuideProvider(boolean enabled, String apiKey, String url, String model, HttpClient http) {
        this(enabled, apiKey, url, model, http, 5000, 6, 300, true);
    }

    GroqSecretGuideProvider(boolean enabled, String apiKey, String url, String model, HttpClient http,
                            int timeoutMillis, int callsPerMinute, int cacheSeconds, boolean allowLoopback) {
        this.enabled = enabled;
        this.apiKey = apiKey;
        this.model = model;
        this.http = http;
        this.timeoutMillis = timeoutMillis;
        this.callsPerMinute = callsPerMinute;
        this.cacheNanos = Duration.ofSeconds(cacheSeconds).toNanos();
        this.configurationValid = timeoutMillis >= 250 && timeoutMillis <= 8000
                && callsPerMinute >= 1 && callsPerMinute <= 6 && cacheSeconds >= 30 && cacheSeconds <= 900;
        URI parsed;
        try { parsed = URI.create(url); } catch (RuntimeException invalidUrl) { parsed = null; }
        this.endpoint = parsed;
        this.endpointAllowed = allowedEndpoint(parsed, allowLoopback)
                && http.followRedirects() == HttpClient.Redirect.NEVER;
    }

    @Override
    public String configurationReason() {
        if (!enabled) return "DISABLED";
        if (apiKey == null || apiKey.isBlank()) return "KEY_MISSING";
        if (apiKey.chars().anyMatch(character -> character < 0x21 || character > 0x7e)) return "KEY_INVALID";
        if (!endpointAllowed) return "ENDPOINT_NOT_ALLOWED";
        if (!MODEL.equals(model)) return "MODEL_NOT_ALLOWED";
        if (!configurationValid) return "CONFIGURATION_INVALID";
        return "READY";
    }

    @Override
    public Optional<List<String>> selectSteps(SecretGuideContext context) {
        return Optional.ofNullable(select(context).codes());
    }

    @Override
    public Selection select(SecretGuideContext context) {
        String configuration = configurationReason();
        if (!"READY".equals(configuration)) return Selection.fallback(configuration, false);
        if (context == null || !context.supportedIssuer()) return Selection.fallback("UNSUPPORTED_ISSUER", false);
        synchronized (this) {
            long now = System.nanoTime();
            cache.values().removeIf(value -> now - value.expiresAt() >= 0);
            var existing = cache.get(context);
            if (existing != null) return existing.selection().cachedCopy();
            if (inFlight) return Selection.fallback("REQUEST_IN_PROGRESS", false);
            if (now - windowStarted >= WINDOW_NANOS) { windowStarted = now; windowCalls = 0; }
            if (windowCalls >= callsPerMinute) return Selection.fallback("CALL_BUDGET_EXHAUSTED", false);
            inFlight = true;
            windowCalls++;
        }
        Selection result;
        try { result = request(context); }
        catch (RuntimeException ignored) { result = Selection.fallback("PROVIDER_UNAVAILABLE", true); }
        synchronized (this) {
            inFlight = false;
            if (cache.size() >= MAX_CACHE_ENTRIES) cache.remove(cache.keySet().iterator().next());
            long ttl = result.codes() == null ? Duration.ofSeconds(15).toNanos() : cacheNanos;
            cache.put(context, new CachedSelection(result, System.nanoTime() + ttl));
        }
        return result;
    }

    private Selection request(SecretGuideContext context) {
        CompletableFuture<HttpResponse<byte[]>> pending = null;
        try {
            HttpRequest request = HttpRequest.newBuilder(endpoint)
                    .timeout(Duration.ofMillis(timeoutMillis))
                    .header("Authorization", "Bearer " + apiKey)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(requestBody(context), StandardCharsets.UTF_8)).build();
            pending = http.sendAsync(request, info -> new BoundedBodySubscriber(info.statusCode() == 200,
                    info.headers().firstValueAsLong("Content-Length").orElse(0) > MAX_RESPONSE_BYTES));
            // Completes only after the bounded body finishes, so stalled bodies share the same deadline.
            HttpResponse<byte[]> response = pending.get(timeoutMillis, TimeUnit.MILLISECONDS);
            if (response.statusCode() == 429) return Selection.fallback("PROVIDER_RATE_LIMITED", true);
            if (response.statusCode() >= 400 && response.statusCode() < 500) return Selection.fallback("PROVIDER_REJECTED", true);
            if (response.statusCode() != 200) return Selection.fallback("PROVIDER_UNAVAILABLE", true);
            return parse(response.body());
        } catch (TimeoutException timedOut) {
            if (pending != null) pending.cancel(true);
            return Selection.fallback("PROVIDER_TIMEOUT", true);
        } catch (InterruptedException interrupted) {
            if (pending != null) pending.cancel(true);
            Thread.currentThread().interrupt();
            return Selection.fallback("PROVIDER_INTERRUPTED", true);
        } catch (ExecutionException failure) {
            Throwable cause = failure.getCause();
            while (cause != null) {
                if (cause instanceof ResponseTooLarge) return Selection.fallback("PROVIDER_RESPONSE_TOO_LARGE", true);
                if (cause instanceof java.net.http.HttpTimeoutException) return Selection.fallback("PROVIDER_TIMEOUT", true);
                cause = cause.getCause();
            }
            return Selection.fallback("PROVIDER_UNAVAILABLE", true);
        } catch (RuntimeException ignored) {
            return Selection.fallback("PROVIDER_UNAVAILABLE", true);
        }
    }

    private Selection parse(byte[] bytes) {
        try {
            JsonNode choices = json.readTree(bytes).path("choices");
            if (!choices.isArray() || choices.size() != 1) return invalid();
            JsonNode choice = choices.path(0);
            if (!"stop".equals(choice.path("finish_reason").asText())) return invalid();
            JsonNode message = choice.path("message");
            if (!message.path("refusal").isMissingNode() && !message.path("refusal").isNull()) return invalid();
            JsonNode content = message.path("content");
            if (!content.isTextual() || content.asText().length() > MAX_CONTENT_CHARS) return invalid();
            JsonNode object = json.readTree(content.asText());
            JsonNode codes = object.path("step_codes");
            if (!object.isObject() || object.size() != 1 || !codes.isArray() || codes.size() < 4 || codes.size() > 6) return invalid();
            List<String> selected = new ArrayList<>(codes.size());
            for (JsonNode code : codes) {
                if (!code.isTextual()) return invalid();
                selected.add(code.asText());
            }
            if (SecretGuideCatalog.fromSelectedCodes(selected).isEmpty()) return invalid();
            return new Selection(List.copyOf(selected), "GROQ_GENERATED", true, false);
        } catch (RuntimeException invalidJson) { return invalid(); }
    }

    private static Selection invalid() { return Selection.fallback("PROVIDER_INVALID_RESPONSE", true); }

    private String requestBody(SecretGuideContext context) {
        var schema = Map.of("type", "object", "properties", Map.of("step_codes", Map.of(
                "type", "array", "items", Map.of("type", "string", "enum", SecretGuideCatalog.stepCodes()))),
                "required", List.of("step_codes"), "additionalProperties", false);
        return json.writeValueAsString(Map.of(
                "model", model, "max_completion_tokens", 512, "reasoning_effort", "low",
                "messages", List.of(Map.of("role", "system", "content", SYSTEM_PROMPT),
                        Map.of("role", "user", "content", json.writeValueAsString(context.externalFields()))),
                "response_format", Map.of("type", "json_schema", "json_schema", Map.of(
                        "name", "secret_response_steps", "strict", true, "schema", schema))));
    }

    private static boolean allowedEndpoint(URI endpoint, boolean allowLoopback) {
        if (endpoint == null || endpoint.getHost() == null || endpoint.getRawUserInfo() != null
                || endpoint.getRawQuery() != null || endpoint.getFragment() != null
                || !API_PATH.equals(endpoint.getRawPath())) return false;
        if ("https".equalsIgnoreCase(endpoint.getScheme()) && "api.groq.com".equalsIgnoreCase(endpoint.getHost())
                && (endpoint.getPort() == -1 || endpoint.getPort() == 443)) return true;
        return allowLoopback && "http".equalsIgnoreCase(endpoint.getScheme())
                && ("127.0.0.1".equals(endpoint.getHost()) || "localhost".equals(endpoint.getHost()));
    }

    private record CachedSelection(Selection selection, long expiresAt) { }
    private static final class ResponseTooLarge extends RuntimeException { }

    /** Cancels before buffering more than 8 KiB, also for chunked bodies with no Content-Length. */
    private static final class BoundedBodySubscriber implements HttpResponse.BodySubscriber<byte[]> {
        private final CompletableFuture<byte[]> body = new CompletableFuture<>();
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private final boolean read;
        private final boolean oversized;
        private Flow.Subscription subscription;

        BoundedBodySubscriber(boolean read, boolean oversized) { this.read = read; this.oversized = oversized; }
        @Override public CompletionStage<byte[]> getBody() { return body; }
        @Override public void onSubscribe(Flow.Subscription value) {
            subscription = value;
            if (!read || oversized) {
                value.cancel();
                if (read && oversized) body.completeExceptionally(new ResponseTooLarge());
                else body.complete(new byte[0]);
            } else value.request(1);
        }
        @Override public void onNext(List<ByteBuffer> buffers) {
            for (ByteBuffer buffer : buffers) {
                if (buffer.remaining() > MAX_RESPONSE_BYTES - bytes.size()) {
                    subscription.cancel();
                    body.completeExceptionally(new ResponseTooLarge());
                    return;
                }
                byte[] chunk = new byte[buffer.remaining()];
                buffer.get(chunk);
                bytes.writeBytes(chunk);
            }
            subscription.request(1);
        }
        @Override public void onError(Throwable failure) { body.completeExceptionally(failure); }
        @Override public void onComplete() { body.complete(bytes.toByteArray()); }
    }
}
