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
    private final boolean keyStoreUnavailable;
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
    private final Map<SecretExplanationContext, CachedExplanation> explanationCache = new LinkedHashMap<>();
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
            @Value("${logssey.secret.guide.claude.api-key-secret-id:}") String secretId,
            @Value("${logssey.secret.guide.claude.aws-region:ap-northeast-1}") String awsRegion,
            @Value("${logssey.secret.aws.collection.credentials-mode:WORKLOAD}") String credentialsMode,
            @Value("${logssey.secret.aws.collection.profile:}") String profile,
            @Value("${logssey.secret.aws.collection.credentials-file:}") String credentialsFile,
            SecretAiCallBudget budget) {
        this(enabled, sourceKey(enabled, apiKey, keyFile, secretId, awsRegion,
                        credentialsMode, profile, credentialsFile), url, model, workspace,
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
        this.keyStoreUnavailable = key.storeUnavailable();
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
        if (keyStoreUnavailable) return "KEY_STORE_UNAVAILABLE";
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
        var reply = postJson(requestBody(context));
        return reply.reasonCode() == null ? parse(reply.body()) : Selection.fallback(reply.reasonCode(), true);
    }

    private ProviderReply postJson(String body) {
        CompletableFuture<HttpResponse<byte[]>> pending = null;
        try {
            var builder = HttpRequest.newBuilder(endpoint).timeout(Duration.ofMillis(timeoutMillis))
                    .header("Authorization", "Bearer " + apiKey).header("anthropic-version", API_VERSION)
                    .header("Content-Type", "application/json").header("Accept", "application/json");
            if (workspace != null && !workspace.isBlank()) builder.header("anthropic-workspace-id", workspace);
            var request = builder.POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)).build();
            pending = http.sendAsync(request, info -> new SecretGuideHttpBody(info.statusCode() == 200,
                    info.headers().firstValueAsLong("Content-Length").orElse(0)));
            var response = pending.get(timeoutMillis, TimeUnit.MILLISECONDS);
            return switch (response.statusCode()) {
                case 200 -> new ProviderReply(response.body(), null);
                case 401 -> new ProviderReply(null, "PROVIDER_AUTHENTICATION_FAILED");
                case 403 -> new ProviderReply(null, "PROVIDER_ACCESS_DENIED");
                case 402 -> new ProviderReply(null, "PROVIDER_BILLING_REQUIRED");
                case 429 -> new ProviderReply(null, "PROVIDER_RATE_LIMITED");
                default -> new ProviderReply(null, response.statusCode() >= 400 && response.statusCode() < 500
                        ? "PROVIDER_REJECTED" : "PROVIDER_UNAVAILABLE");
            };
        } catch (TimeoutException timeout) {
            if (pending != null) pending.cancel(true);
            return new ProviderReply(null, "PROVIDER_TIMEOUT");
        } catch (InterruptedException interrupted) {
            if (pending != null) pending.cancel(true);
            Thread.currentThread().interrupt();
            return new ProviderReply(null, "PROVIDER_INTERRUPTED");
        } catch (ExecutionException failure) {
            for (Throwable cause = failure.getCause(); cause != null; cause = cause.getCause()) {
                if (cause instanceof SecretGuideHttpBody.ResponseTooLarge) return new ProviderReply(null, "PROVIDER_RESPONSE_TOO_LARGE");
                if (cause instanceof java.net.http.HttpTimeoutException) return new ProviderReply(null, "PROVIDER_TIMEOUT");
            }
            return new ProviderReply(null, "PROVIDER_UNAVAILABLE");
        }
    }

    Explanation explain(SecretExplanationContext context) {
        String readiness = configurationReason();
        if (!"READY".equals(readiness)) return Explanation.fallback(readiness, false);
        synchronized (this) {
            long now = System.nanoTime();
            explanationCache.values().removeIf(value -> now - value.expiresAt() >= 0);
            var existing = explanationCache.get(context);
            if (existing != null) return existing.explanation().cachedCopy();
            if (inFlight) return Explanation.fallback("REQUEST_IN_PROGRESS", false);
            if (now - windowStarted >= WINDOW_NANOS) { windowStarted = now; windowCalls = 0; }
            if (windowCalls >= callsPerMinute) return Explanation.fallback("CALL_BUDGET_EXHAUSTED", false);
            inFlight = true;
            windowCalls++;
        }
        Explanation result;
        boolean called = false;
        try (var permit = budget == null ? SecretAiCallBudget.Permit.unmeteredForTests()
                : budget.acquire(providerId(), modelId(), "BRIEFING", Duration.ofMillis(timeoutMillis))) {
            if (permit.allowed()) {
                called = true;
                var reply = postJson(explanationBody(context));
                result = reply.reasonCode() == null ? parseExplanation(reply.body(), context)
                        : Explanation.fallback(reply.reasonCode(), true);
            } else {
                result = Explanation.fallback(permit.reasonCode(), false);
            }
        } catch (RuntimeException unavailable) {
            result = Explanation.fallback("PROVIDER_UNAVAILABLE", called);
        }
        synchronized (this) {
            inFlight = false;
            if (explanationCache.size() >= MAX_CACHE_ENTRIES) {
                explanationCache.remove(explanationCache.keySet().iterator().next());
            }
            long ttl = result.summary() == null ? Duration.ofSeconds(15).toNanos() : cacheNanos;
            explanationCache.put(context, new CachedExplanation(result, System.nanoTime() + ttl));
        }
        return result;
    }

    private String explanationBody(SecretExplanationContext context) {
        var schema = Map.of("type", "object", "properties", Map.of(
                "summary", Map.of("type", "string"),
                "fact_codes", Map.of("type", "array", "items", Map.of("type", "string", "enum", context.facts())),
                "action_codes", Map.of("type", "array", "items", Map.of("type", "string", "enum", context.actions()))),
                "required", List.of("summary", "fact_codes", "action_codes"), "additionalProperties", false);
        String instructions = """
                Explain the supplied server observations in Korean in at most three short sentences.
                Explain completed work, remaining uncertainty and the useful next steps together.
                Return every supplied fact code and select at most three distinct allowed action codes.
                Use only the supplied facts. Never infer token expiry, revocation, abuse, permission,
                severity, safety, or completion. A completed validation stage means processing ended,
                not that all keys are valid. Partial coverage cannot prove global absence or retirement.
                Authentication rejection does not identify expiry or revocation. Metadata inventory
                does not authenticate secret values. Never suggest entering or revealing a secret.
                sourceProvider is where content was collected; issuer is the key's issuing service.
                A GitHub scan can contain AWS or Notion credentials. MIXED means multiple or unknown types.
                Suggest only allowed actions. Do not generate URLs, shell commands or configuration.
                Do not claim a retry will happen unless RETRY_SCHEDULED is present.
                The vocabulary below contains public UI definitions, not customer content.
                """ + json.writeValueAsString(Map.of("facts", SecretExplanationCatalog.publicFacts(),
                        "actions", SecretExplanationCatalog.publicActions()));
        return json.writeValueAsString(Map.of("model", model, "max_tokens", 768,
                "system", instructions, "thinking", Map.of("type", "between_tools"),
                "messages", List.of(Map.of("role", "user", "content", json.writeValueAsString(context.externalFields()))),
                "output_config", Map.of("effort", "low", "format", Map.of("type", "json_schema", "schema", schema))));
    }

    private Explanation parseExplanation(byte[] bytes, SecretExplanationContext context) {
        try {
            JsonNode message = json.readTree(bytes);
            if (!"message".equals(message.path("type").asText())
                    || !"assistant".equals(message.path("role").asText())
                    || !"end_turn".equals(message.path("stop_reason").asText())
                    || !message.path("content").isArray()) return Explanation.fallback("PROVIDER_INVALID_RESPONSE", true);
            String text = null;
            for (JsonNode block : message.path("content")) {
                if ("text".equals(block.path("type").asText())) {
                    if (text != null || !block.path("text").isTextual()) return Explanation.fallback("PROVIDER_INVALID_RESPONSE", true);
                    text = block.path("text").asText();
                } else if (!List.of("thinking", "redacted_thinking").contains(block.path("type").asText())) {
                    return Explanation.fallback("PROVIDER_INVALID_RESPONSE", true);
                }
            }
            if (text == null || text.length() > MAX_CONTENT_CHARS) return Explanation.fallback("PROVIDER_INVALID_RESPONSE", true);
            var value = json.readTree(text);
            String summary = value.path("summary").asText("");
            if (!value.isObject() || value.size() != 3 || !value.path("summary").isTextual()
                    || !safeExplanation(summary)) return Explanation.fallback("PROVIDER_INVALID_RESPONSE", true);
            var facts = stringCodes(value.path("fact_codes"));
            var actions = stringCodes(value.path("action_codes"));
            if (facts == null || actions == null || !java.util.Set.copyOf(facts).equals(java.util.Set.copyOf(context.facts()))
                    || facts.size() != context.facts().size() || actions.size() > 3
                    || java.util.Set.copyOf(actions).size() != actions.size()
                    || !context.actions().containsAll(actions)) return Explanation.fallback("PROVIDER_INVALID_RESPONSE", true);
            return new Explanation(summary, List.copyOf(actions), "CLAUDE_GENERATED", true, false, java.time.Instant.now());
        } catch (RuntimeException invalid) {
            return Explanation.fallback("PROVIDER_INVALID_RESPONSE", true);
        }
    }

    private static List<String> stringCodes(JsonNode array) {
        if (!array.isArray() || array.size() > 24) return null;
        var codes = new ArrayList<String>();
        for (JsonNode item : array) {
            if (!item.isTextual()) return null;
            codes.add(item.asText());
        }
        return codes;
    }

    private static boolean safeExplanation(String text) {
        if (text.isBlank() || text.length() > 600 || text.chars().anyMatch(value -> value < 0x20 && value != '\n')) return false;
        return !java.util.regex.Pattern.compile(
                "(?i)https?://|www\\.|arn:|sk-ant-|ghp_|github_pat_|ntn_|-----BEGIN|[<>`]|"
                        + "\\b(curl|kubectl|sudo|powershell|terraform)\\b|"
                        + "만료되었습니다|폐기되었습니다|악용되었습니다|모두 해결|안전합니다|위험이 없습니다|유효합니다|무효입니다")
                .matcher(text).find();
    }

    record Explanation(String summary, List<String> actionCodes, String reasonCode,
                       boolean providerCalled, boolean cached, java.time.Instant generatedAt) {
        static Explanation fallback(String reason, boolean called) {
            return new Explanation(null, List.of(), reason, called, false, null);
        }
        Explanation cachedCopy() {
            return new Explanation(summary, actionCodes, reasonCode, false, true, generatedAt);
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

    private static Key sourceKey(boolean enabled, String apiKey, String keyFile, String secretId,
                                 String region, String mode, String profile, String credentialsFile) {
        if (!enabled || secretId == null || secretId.isBlank()) return key(apiKey, keyFile);
        // The configured managed source is authoritative, including on read failures.
        try {
            return new Key(ClaudeApiKeySource.read(secretId, region, mode, profile, credentialsFile), false);
        } catch (RuntimeException unavailable) {
            return new Key(null, false, true);
        }
    }

    private record Key(String value, boolean unreadable, boolean storeUnavailable) {
        Key(String value, boolean unreadable) { this(value, unreadable, false); }
        @Override public String toString() { return "ClaudeKey[redacted]"; }
    }
    private record CachedSelection(Selection selection, long expiresAt) { }
    private record CachedExplanation(Explanation explanation, long expiresAt) { }
    private record ProviderReply(byte[] body, String reasonCode) { }
}
