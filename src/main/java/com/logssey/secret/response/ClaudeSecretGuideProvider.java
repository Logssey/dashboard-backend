package com.logssey.secret.response;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Claude selects bounded catalog steps from five enum facts. Provider text is never displayed. */
@Component
@ConditionalOnProperty(name = "logssey.secret.guide.provider", havingValue = "claude", matchIfMissing = true)
class ClaudeSecretGuideProvider implements SecretGuideProvider {
    static final String MODEL = "claude-sonnet-5-5";
    private static final String API_PATH = "/v1/messages";
    private static final String API_VERSION = "2026-10-21";
    private static final int MAX_CONTENT_CHARS = 2_048;
    private static final int MAX_CACHE_ENTRIES = 128;
    private static final long WINDOW_NANOS = Duration.ofMinutes(1).toNanos();
    private static final String SYSTEM_PROMPT = """
            Select secret-response guide step codes for the supplied enum facts.
            Return only the schema object. Never infer severity, permissions, compromise,
            token expiration, revocation, exposure, or task completion.
            Begin with VERIFY_EXPOSURE, end with REVALIDATE, and place EXTERNAL_ROTATION
            before RECORD_ACTION. Include those four required codes exactly once.
            Include REVIEW_USAGE and REVIEW_PERMISSIONS when they help the stated workflow.
            INVALID means authentication was rejected; the cause is unknown. Prioritize
            checking existing replacement/revocation and cleaning source copies.
            UNKNOWN or UNCHECKED means authentication remains unconfirmed; verify available
            credential components and current evidence before selecting optional review work.
            """;

    private final SecretAiCallBudget budget;
    private final boolean enabled;
    private final String apiKey;
    private final boolean keyFileUnreadable;
    private final URI endpoint;
    private final String model;
    private final String workspace;
    private final HttpClient http;
    private final int timeoutMillis;
    private final int callsPerMinute;
    private final long cacheNanos;
    private final boolean configurationValid;
    private final boolean endpointAllowed;
    private final JsonMapper json = new JsonMapper();
    private final Map<SecretGuideContext, CachedSelection> cache = new LinkedHashMap<>();
    private long windowStarted = System.nanoTime();
    private int windowCalls;
    private boolean inFlight;

    @Autowired
    ClaudeSecretGuideProvider(@Value("${logssey.secret.guide.claude.enabled:false}") boolean enabled,
            @Value("${logssey.secret.guide.claude.api-key:}") String apiKey,
            @Value("${logssey.secret.guide.claude.api-key-file:}") String keyFile,
            @Value("${logssey.secret.guide.claude.url:https://api.anthropic.com/v1/messages}") String url,
            @Value("${logssey.secret.guide.claude.model:claude-sonnet-5-5}") String model,
            @Value("${logssey.secret.guide.claude.workspace-id:}") String workspace,
            @Value("${logssey.secret.guide.claude.timeout-ms:45000}") int timeoutMillis,
            @Value("${logssey.secret.guide.claude.calls-per-minute:6}") int callsPerMinute,
            @Value("${logssey.secret.guide.claude.cache-seconds:300}") int cacheSeconds,
            SecretAiCallBudget budget) {
        this(enabled, key(apiKey, keyFile), url, model, workspace,
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3))
                        .followRedirects(HttpClient.Redirect.NEVER).build(),
                timeoutMillis, callsPerMinute, cacheSeconds, false, java.util.Objects.requireNonNull(budget));
    }

    ClaudeSecretGuideProvider(boolean enabled, String apiKey, String keyFile, String url, String model,
            String workspace, int timeoutMillis, int callsPerMinute, int cacheSeconds) {
        this(enabled, key(apiKey, keyFile), url, model, workspace,
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3))
                        .followRedirects(HttpClient.Redirect.NEVER).build(),
                timeoutMillis, callsPerMinute, cacheSeconds, false, null);
    }

    /** Loopback is enabled only by package-local HTTP tests. */
    ClaudeSecretGuideProvider(boolean enabled, String apiKey, String url, String model,
            String workspace, HttpClient http, int timeoutMillis, int callsPerMinute, int cacheSeconds) {
        this(enabled, new Key(apiKey, false), url, model, workspace, http,
                timeoutMillis, callsPerMinute, cacheSeconds, true, null);
    }

    ClaudeSecretGuideProvider(boolean enabled, String apiKey, String url, String model,
            String workspace, HttpClient http, int timeoutMillis, int callsPerMinute, int cacheSeconds,
            SecretAiCallBudget budget) {
        this(enabled, new Key(apiKey, false), url, model, workspace, http,
                timeoutMillis, callsPerMinute, cacheSeconds, true, java.util.Objects.requireNonNull(budget));
    }

    private ClaudeSecretGuideProvider(boolean enabled, Key key, String url, String model,
            String workspace, HttpClient http, int timeoutMillis, int callsPerMinute,
            int cacheSeconds, boolean allowLoopback, SecretAiCallBudget budget) {
        this.budget = budget;
        this.enabled = enabled;
        this.apiKey = key.value();
        this.keyFileUnreadable = key.unreadable();
        this.model = model;
        this.workspace = workspace;
        this.http = http;
        this.timeoutMillis = timeoutMillis;
        this.callsPerMinute = callsPerMinute;
        this.cacheNanos = Duration.ofSeconds(cacheSeconds).toNanos();
        this.configurationValid = timeoutMillis >= 250 && timeoutMillis <= 60000
                && callsPerMinute >= 1 && callsPerMinute <= 6 && cacheSeconds >= 30 && cacheSeconds <= 900;
        URI parsed;
        try { parsed = URI.create(url); } catch (RuntimeException invalid) { parsed = null; }
        this.endpoint = parsed;
        this.endpointAllowed = allowedEndpoint(parsed, allowLoopback)
                && http.followRedirects() == HttpClient.Redirect.NEVER;
    }

    @Override public String providerId() { return "CLAUDE"; }
    @Override public String modelId() { return MODEL.equals(model) ? model : null; }

    @Override public String configurationReason() {
        if (!enabled) return "DISABLED";
        if (keyFileUnreadable) return "KEY_FILE_UNREADABLE";
        if (apiKey == null || apiKey.isBlank()) return "KEY_MISSING";
        if (apiKey.chars().anyMatch(character -> character < 0x21 || character > 0x7e)) return "KEY_INVALID";
        if (workspace != null && !workspace.isBlank() && !workspace.matches("wrkspc_[A-Za-z0-9]{1,100}")) return "WORKSPACE_INVALID";
        if (!endpointAllowed) return "ENDPOINT_NOT_ALLOWED";
        if (!MODEL.equals(model)) return "MODEL_NOT_ALLOWED";
        if (!configurationValid) return "CONFIGURATION_INVALID";
        return "READY";
    }

    @Override public Optional<List<String>> selectSteps(SecretGuideContext context) {
        return Optional.ofNullable(select(context).codes());
    }

    @Override public Selection select(SecretGuideContext context) {
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
        boolean providerCalled = false;
        try (var permit = budget == null ? SecretAiCallBudget.Permit.unmeteredForTests()
                : budget.acquire(providerId(), modelId(), "GUIDE", Duration.ofMillis(timeoutMillis))) {
            if (permit.allowed()) {
                providerCalled = true;
                result = request(context);
            } else {
                result = Selection.fallback(permit.reasonCode(), false);
            }
        } catch (RuntimeException ignored) { result = Selection.fallback("PROVIDER_UNAVAILABLE", providerCalled); }
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
            var builder = HttpRequest.newBuilder(endpoint).timeout(Duration.ofMillis(timeoutMillis))
                    .header("Authorization", "Bearer " + apiKey).header("anthropic-version", API_VERSION)
                    .header("Content-Type", "application/json").header("Accept", "application/json");
            if (workspace != null && !workspace.isBlank()) builder.header("anthropic-workspace-id", workspace);
            var request = builder.POST(HttpRequest.BodyPublishers.ofString(requestBody(context), StandardCharsets.UTF_8)).build();
            pending = http.sendAsync(request, info -> new SecretGuideHttpBody(info.statusCode() == 200,
                    info.headers().firstValueAsLong("Content-Length").orElse(0)));
            var response = pending.get(timeoutMillis, TimeUnit.MILLISECONDS);
            return switch (response.statusCode()) {
                case 200 -> parse(response.body());
                case 401 -> Selection.fallback("PROVIDER_AUTHENTICATION_FAILED", true);
                case 403 -> Selection.fallback("PROVIDER_ACCESS_DENIED", true);
                case 402 -> Selection.fallback("PROVIDER_BILLING_REQUIRED", true);
                case 429 -> Selection.fallback("PROVIDER_RATE_LIMITED", true);
                default -> Selection.fallback(response.statusCode() >= 400 && response.statusCode() < 500
                        ? "PROVIDER_REJECTED" : "PROVIDER_UNAVAILABLE", true);
            };
        } catch (TimeoutException timeout) {
            if (pending != null) pending.cancel(true);
            return Selection.fallback("PROVIDER_TIMEOUT", true);
        } catch (InterruptedException interrupted) {
            if (pending != null) pending.cancel(true);
            Thread.currentThread().interrupt();
            return Selection.fallback("PROVIDER_INTERRUPTED", true);
        } catch (ExecutionException failure) {
            for (Throwable cause = failure.getCause(); cause != null; cause = cause.getCause()) {
                if (cause instanceof SecretGuideHttpBody.ResponseTooLarge) return Selection.fallback("PROVIDER_RESPONSE_TOO_LARGE", true);
                if (cause instanceof java.net.http.HttpTimeoutException) return Selection.fallback("PROVIDER_TIMEOUT", true);
            }
            return Selection.fallback("PROVIDER_UNAVAILABLE", true);
        }
    }

    private Selection parse(byte[] bytes) {
        try {
            JsonNode message = json.readTree(bytes);
            if (!"message".equals(message.path("type").asText())
                    || !"assistant".equals(message.path("role").asText())
                    || !"end_turn".equals(message.path("stop_reason").asText())
                    || "refusal".equals(message.path("stop_details").path("type").asText())) return invalid();
            JsonNode content = message.path("content");
            if (!content.isArray()) return invalid();
            String text = null;
            for (JsonNode block : content) {
                String type = block.path("type").asText();
                if ("text".equals(type)) {
                    if (text != null || !block.path("text").isTextual()) return invalid();
                    text = block.path("text").asText();
                } else if (!"thinking".equals(type) && !"redacted_thinking".equals(type)) return invalid();
            }
            if (text == null || text.length() > MAX_CONTENT_CHARS) return invalid();
            JsonNode object = json.readTree(text);
            JsonNode codes = object.path("step_codes");
            if (!object.isObject() || object.size() != 1 || !codes.isArray() || codes.size() < 4 || codes.size() > 6) return invalid();
            var selected = new ArrayList<String>(codes.size());
            for (JsonNode code : codes) {
                if (!code.isTextual()) return invalid();
                selected.add(code.asText());
            }
            if (SecretGuideCatalog.fromSelectedCodes(selected).isEmpty()) return invalid();
            return new Selection(List.copyOf(selected), "CLAUDE_GENERATED", true, false);
        } catch (RuntimeException invalid) { return invalid(); }
    }

    private String requestBody(SecretGuideContext context) {
        var schema = Map.of("type", "object", "properties", Map.of("step_codes", Map.of(
                "type", "array", "items", Map.of("type", "string", "enum", SecretGuideCatalog.stepCodes()))),
                "required", List.of("step_codes"), "additionalProperties", false);
        return json.writeValueAsString(Map.of("model", model, "max_tokens", 768,
                "system", SYSTEM_PROMPT, "thinking", Map.of("type", "between_tools"),
                "messages", List.of(Map.of("role", "user", "content", json.writeValueAsString(context.externalFields()))),
                "output_config", Map.of("effort", "low", "format", Map.of("type", "json_schema", "schema", schema))));
    }

    private static Selection invalid() { return Selection.fallback("PROVIDER_INVALID_RESPONSE", true); }

    private static boolean allowedEndpoint(URI endpoint, boolean allowLoopback) {
        if (endpoint == null || endpoint.getHost() == null || endpoint.getRawUserInfo() != null
                || endpoint.getRawQuery() != null || endpoint.getFragment() != null || !API_PATH.equals(endpoint.getRawPath())) return false;
        if ("https".equalsIgnoreCase(endpoint.getScheme()) && "api.anthropic.com".equalsIgnoreCase(endpoint.getHost())
                && (endpoint.getPort() == -1 || endpoint.getPort() == 443)) return true;
        return allowLoopback && "http".equalsIgnoreCase(endpoint.getScheme())
                && ("127.0.0.1".equals(endpoint.getHost()) || "localhost".equals(endpoint.getHost()));
    }

    private static Key key(String apiKey, String keyFile) {
        if (apiKey != null && !apiKey.isBlank() || keyFile == null || keyFile.isBlank()) return new Key(apiKey, false);
        try (var input = Files.newInputStream(Path.of(keyFile))) {
            byte[] bytes = input.readNBytes(4_097);
            if (bytes.length > 4_096) return new Key(null, true);
            String text = new String(bytes, StandardCharsets.UTF_8);
            if (text.startsWith("\uFEFF")) text = text.substring(1);
            return new Key(text.strip(), false);
        } catch (java.io.IOException | RuntimeException unavailable) { return new Key(null, true); }
    }

    private record Key(String value, boolean unreadable) { }
    private record CachedSelection(Selection selection, long expiresAt) { }
}
