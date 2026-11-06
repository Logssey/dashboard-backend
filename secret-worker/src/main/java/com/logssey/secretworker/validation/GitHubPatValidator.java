package com.logssey.secretworker.validation;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.util.Timeout;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.net.SocketTimeoutException;
import java.net.URI;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

/** A discovered PAT authenticates only against the fixed registered /user endpoint. */
@Component
public final class GitHubPatValidator {
    public static final String METHOD = "GITHUB_GET_AUTHENTICATED_USER";
    public static final String VERSION = "1";
    public static final String API_VERSION = "2026-03-10";
    private static final int MAX_BYTES = 65_536;
    private final boolean enabled;
    private final URI endpoint;
    private final Duration timeout;
    private final JsonMapper json = new JsonMapper();

    @org.springframework.beans.factory.annotation.Autowired
    public GitHubPatValidator(
            @Value("${logssey.secret.validation.github.enabled:false}") boolean enabled) {
        this(enabled, URI.create("https://api.github.com/user"), Duration.ofSeconds(8));
    }

    // Package-private test seam; never sourced from a connection, finding, URL or API request.
    GitHubPatValidator(boolean enabled, URI endpoint, Duration timeout) {
        if (!("https://api.github.com/user".equals(endpoint.toString())
                || "http".equals(endpoint.getScheme())
                        && "127.0.0.1".equals(endpoint.getHost())
                        && "/user".equals(endpoint.getPath())
                        && endpoint.getQuery() == null
                        && endpoint.getFragment() == null))
            throw new IllegalArgumentException("UNREGISTERED_VALIDATION_ENDPOINT");
        this.enabled = enabled;
        this.endpoint = endpoint;
        this.timeout = timeout;
    }

    public boolean enabled() {
        return enabled
                && System.getProperty("jdk.httpclient.HttpClient.log", "").isBlank()
                && !LoggerFactory.getLogger("org.apache.hc.client5.http").isDebugEnabled()
                && !LoggerFactory.getLogger("org.apache.hc.client5.http.headers").isDebugEnabled()
                && !LoggerFactory.getLogger("org.apache.hc.client5.http.wire").isDebugEnabled();
    }

    public CredentialValidationResult validate(String token) {
        if (!enabled()) return CredentialValidationResult.unchecked("DISABLED");
        if (token == null
                || !(token.matches("ghp_[A-Za-z0-9_]{36}")
                        || token.matches("github_pat_[A-Za-z0-9_]{70,}")))
            return CredentialValidationResult.unchecked("INCOMPLETE_COMPONENTS");
        var request = new HttpGet(endpoint);
        request.setHeader("Authorization", "Bearer " + token);
        request.setHeader("Accept", "application/vnd.github+json");
        request.setHeader("User-Agent", "logssey-secret-worker");
        request.setHeader("X-GitHub-Api-Version", API_VERSION);
        var connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
                .setDefaultConnectionConfig(ConnectionConfig.custom()
                        .setConnectTimeout(Timeout.ofSeconds(3)).build()).build();
        // One leased validation attempt permits one wire request, including an EOF failure.
        var http = HttpClients.custom()
                .setConnectionManager(connectionManager)
                .setDefaultRequestConfig(RequestConfig.custom()
                        .setConnectionRequestTimeout(Timeout.ofSeconds(3))
                        .setResponseTimeout(Timeout.ofMilliseconds(timeout.toMillis())).build())
                .disableAutomaticRetries().disableRedirectHandling().disableCookieManagement()
                .disableAuthCaching().disableContentCompression().build();
        var executor = Executors.newVirtualThreadPerTaskExecutor();
        var headerResult = new AtomicReference<CredentialValidationResult>();
        Future<CredentialValidationResult> pending = null;
        try {
            pending = executor.submit(() -> {
                var response = http.executeOpen(null, request, null);
                try {
                    var metadata = metadataResult(response, Instant.now());
                    if (metadata != null) {
                        headerResult.set(metadata);
                        return metadata;
                    }
                    byte[] body = response.getEntity() == null ? new byte[0]
                            : response.getEntity().getContent().readNBytes(MAX_BYTES + 1);
                    try {
                        if (body.length > MAX_BYTES)
                            return CredentialValidationResult.unknown("UNEXPECTED_RESPONSE");
                        return interpret(response, body, token.startsWith("ghp_"));
                    } finally {
                        Arrays.fill(body, (byte) 0);
                    }
                } finally {
                    // Do not let error-body consumption turn an observed cooldown into a timeout.
                    request.cancel();
                    try { response.close(); } catch (java.io.IOException ignored) { /* already cancelled */ }
                }
            });
            return pending.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
            return CredentialValidationResult.unknown("CLIENT_FAILURE");
        } catch (TimeoutException ignored) {
            return headerResult.get() != null ? headerResult.get()
                    : CredentialValidationResult.unknown("PROVIDER_UNAVAILABLE");
        } catch (ExecutionException error) {
            return headerResult.get() != null ? headerResult.get()
                    : CredentialValidationResult.unknown(error.getCause() instanceof SocketTimeoutException
                    ? "PROVIDER_UNAVAILABLE" : "CLIENT_FAILURE");
        } catch (RuntimeException ignored) {
            return CredentialValidationResult.unknown("CLIENT_FAILURE");
        } finally {
            request.cancel();
            if (pending != null && !pending.isDone()) pending.cancel(true);
            http.close(CloseMode.IMMEDIATE);
            executor.shutdownNow();
        }
    }

    private CredentialValidationResult interpret(HttpResponse response, byte[] body, boolean classic) {
        Instant at = Instant.now();
        int status = response.getCode();
        JsonNode root;
        try {
            root = json.readTree(body);
        } catch (RuntimeException ignored) {
            return result("UNKNOWN", "UNEXPECTED_RESPONSE", at, status);
        }
        if (root == null || !root.isObject()) return result("UNKNOWN", "UNEXPECTED_RESPONSE", at, status);
        if (status == 401) {
            // Authentication rejection is an observation, not an expiry/revocation cause.
            boolean rejected = "Bad credentials".equals(root.path("message").asText(""));
            return result(rejected ? "INVALID" : "UNKNOWN",
                    rejected ? "AUTHENTICATION_REJECTED" : "UNEXPECTED_RESPONSE", at, status);
        }
        boolean principal = root.path("id").isIntegralNumber() && root.path("id").asLong(0) > 0
                && root.path("login").isTextual() && !root.path("login").asText("").isBlank();
        return new CredentialValidationResult(principal ? "VALID" : "UNKNOWN",
                principal ? "AUTHENTICATED" : "UNEXPECTED_RESPONSE", at, status, null,
                principal ? com.logssey.secret.permission.core.SecretProviderIdentity.github(
                        root.path("id").asLong(), classic,
                        response.getFirstHeader("X-OAuth-Scopes") == null ? null
                                : header(response, "X-OAuth-Scopes")) : null);
    }

    private static CredentialValidationResult metadataResult(HttpResponse response, Instant at) {
        int status = response.getCode();
        if (status == 429 || status == 403 && ("0".equals(header(response, "X-RateLimit-Remaining"))
                || !header(response, "Retry-After").isBlank()))
            return new CredentialValidationResult("UNKNOWN", "RATE_LIMITED", at, status, retryAt(response, at));
        if (status >= 500)
            return new CredentialValidationResult("UNKNOWN", "PROVIDER_UNAVAILABLE", at, status,
                    header(response, "Retry-After").isBlank() ? null : retryAt(response, at));
        if (status == 403 || status == 404) return result("UNKNOWN", "ACCESS_LIMITED", at, status);
        if (status != 200 && status != 401) return result("UNKNOWN", "UNEXPECTED_RESPONSE", at, status);
        return null;
    }

    private static CredentialValidationResult result(String result, String reason, Instant at, int status) {
        return new CredentialValidationResult(result, reason, at, status, null);
    }

    private static String header(HttpResponse response, String name) {
        var value = response.getFirstHeader(name);
        return value == null ? "" : value.getValue();
    }

    private static Instant retryAt(HttpResponse response, Instant at) {
        Instant retry = retryAfter(header(response, "Retry-After"), at);
        Instant reset = null;
        if ("0".equals(header(response, "X-RateLimit-Remaining"))) {
            try {
                reset = Instant.ofEpochSecond(Long.parseLong(header(response, "X-RateLimit-Reset")));
            } catch (RuntimeException ignored) { /* absent or malformed reset uses the other signal */ }
        }
        if (reset != null && (retry == null || reset.isAfter(retry))) retry = reset;
        return retry == null ? at.plusSeconds(60) : retry.isAfter(at) ? retry : at.plusSeconds(1);
    }

    private static Instant retryAfter(String value, Instant at) {
        try {
            return at.plusSeconds(Math.max(1, Long.parseLong(value)));
        } catch (RuntimeException ignored) {
            try {
                return ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
            } catch (RuntimeException ignoredDate) {
                return null;
            }
        }
    }
}
