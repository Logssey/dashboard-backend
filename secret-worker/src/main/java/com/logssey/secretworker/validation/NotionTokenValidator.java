package com.logssey.secretworker.validation;

import com.logssey.secret.permission.core.SecretProviderIdentity;
import java.net.SocketTimeoutException;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.util.Timeout;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Authenticates a discovered content API token against Notion's registered self endpoint. */
@Component
public final class NotionTokenValidator {
    public static final String METHOD = "NOTION_GET_SELF";
    public static final String VERSION = "1";
    public static final String API_VERSION = "2026-03-11";
    private static final int MAX_BYTES = 65_536;
    private static final Pattern UUID = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

    private final boolean configured;
    private final URI endpoint;
    private final Duration timeout;
    private final JsonMapper json = new JsonMapper();

    @Autowired
    public NotionTokenValidator(
            @Value("${logssey.secret.validation.notion.enabled:false}") boolean enabled) {
        this(enabled, URI.create("https://api.notion.com/v1/users/me"), Duration.ofSeconds(8));
    }

    // The loopback endpoint is a test seam and never accepts a finding or connection URL.
    NotionTokenValidator(boolean enabled, URI endpoint, Duration timeout) {
        boolean registered = "https://api.notion.com/v1/users/me".equals(endpoint.toString());
        boolean loopback = "http".equals(endpoint.getScheme())
                && "127.0.0.1".equals(endpoint.getHost())
                && "/v1/users/me".equals(endpoint.getPath())
                && endpoint.getUserInfo() == null
                && endpoint.getQuery() == null
                && endpoint.getFragment() == null;
        if (!registered && !loopback) {
            throw new IllegalArgumentException("UNREGISTERED_VALIDATION_ENDPOINT");
        }
        this.configured = enabled;
        this.endpoint = endpoint;
        this.timeout = timeout;
    }

    public boolean enabled() {
        return configured
                && System.getProperty("jdk.httpclient.HttpClient.log", "").isBlank()
                && !LoggerFactory.getLogger("org.apache.hc.client5.http").isDebugEnabled()
                && !LoggerFactory.getLogger("org.apache.hc.client5.http.headers").isDebugEnabled()
                && !LoggerFactory.getLogger("org.apache.hc.client5.http.wire").isDebugEnabled();
    }

    static boolean supportedShape(String token) {
        return token != null
                && (token.matches("ntn_[A-Za-z0-9_]{46}")
                        || token.matches("secret_[A-Za-z0-9]{43}"));
    }

    public CredentialValidationResult validate(String token) {
        if (!enabled()) return CredentialValidationResult.unchecked("DISABLED");
        if (!supportedShape(token)) {
            return CredentialValidationResult.unchecked("INCOMPLETE_COMPONENTS");
        }

        var request = new HttpGet(endpoint);
        request.setHeader("Authorization", "Bearer " + token);
        request.setHeader("Notion-Version", API_VERSION);
        request.setHeader("Accept", "application/json");
        request.setHeader("User-Agent", "logssey-secret-worker");
        var connectionManager = PoolingHttpClientConnectionManagerBuilder.create()
                .setDefaultConnectionConfig(ConnectionConfig.custom()
                        .setConnectTimeout(Timeout.ofSeconds(3)).build())
                .build();
        var http = HttpClients.custom()
                .setConnectionManager(connectionManager)
                .setDefaultRequestConfig(RequestConfig.custom()
                        .setConnectionRequestTimeout(Timeout.ofSeconds(3))
                        .setResponseTimeout(Timeout.ofMilliseconds(timeout.toMillis())).build())
                .disableAutomaticRetries()
                .disableRedirectHandling()
                .disableCookieManagement()
                .disableAuthCaching()
                .disableContentCompression()
                .build();
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
                        // A 429 body can identify an access block that should not be retried.
                        if (response.getCode() != 429) return metadata;
                    }
                    byte[] body = response.getEntity() == null
                            ? new byte[0]
                            : response.getEntity().getContent().readNBytes(MAX_BYTES + 1);
                    try {
                        if (body.length > MAX_BYTES) {
                            return metadata != null
                                    ? metadata
                                    : result("UNKNOWN", "UNEXPECTED_RESPONSE", Instant.now(),
                                            response.getCode());
                        }
                        return interpret(response, body, metadata);
                    } finally {
                        Arrays.fill(body, (byte) 0);
                    }
                } finally {
                    request.cancel();
                    try {
                        response.close();
                    } catch (java.io.IOException ignored) {
                        // Cancellation has already closed the response stream.
                    }
                }
            });
            return pending.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
            return headerResult.get() != null
                    ? headerResult.get()
                    : CredentialValidationResult.unknown("CLIENT_FAILURE");
        } catch (TimeoutException ignored) {
            return headerResult.get() != null
                    ? headerResult.get()
                    : CredentialValidationResult.unknown("PROVIDER_UNAVAILABLE");
        } catch (ExecutionException error) {
            return headerResult.get() != null
                    ? headerResult.get()
                    : CredentialValidationResult.unknown(
                            error.getCause() instanceof SocketTimeoutException
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

    private CredentialValidationResult interpret(
            HttpResponse response, byte[] body, CredentialValidationResult metadata) {
        Instant at = Instant.now();
        int status = response.getCode();
        JsonNode root;
        try {
            root = json.readTree(body);
        } catch (RuntimeException ignored) {
            return metadata != null ? metadata : result("UNKNOWN", "UNEXPECTED_RESPONSE", at, status);
        }
        if (root == null || !root.isObject()) {
            return metadata != null ? metadata : result("UNKNOWN", "UNEXPECTED_RESPONSE", at, status);
        }
        if (status == 429) {
            boolean blocked = "rate_limited".equals(root.path("code").asText(""))
                    && "public_api_request_blocked".equals(
                            root.path("additional_data").path("rate_limit_reason").asText(""));
            return blocked ? result("UNKNOWN", "PROVIDER_ACCESS_BLOCKED", at, status) : metadata;
        }
        if (status == 401) {
            // The provider confirms current rejection, without identifying expiry or revocation.
            boolean rejected = "unauthorized".equals(root.path("code").asText(""));
            return result(rejected ? "INVALID" : "UNKNOWN",
                    rejected ? "AUTHENTICATION_REJECTED" : "UNEXPECTED_RESPONSE", at, status);
        }

        String principalId = uuid(root.path("id"));
        String type = root.path("type").asText("");
        boolean authenticated = "user".equals(root.path("object").asText(""))
                && principalId != null
                && ("bot".equals(type) || "person".equals(type));
        SecretProviderIdentity identity = null;
        if (authenticated && "bot".equals(type)) {
            String workspaceRef = uuid(root.path("bot").path("workspace_id"));
            String ownerType = root.path("bot").path("owner").path("type").asText("");
            identity = SecretProviderIdentity.notion(principalId, workspaceRef,
                    "user".equals(ownerType) || "workspace".equals(ownerType) ? ownerType : null);
        }
        return new CredentialValidationResult(authenticated ? "VALID" : "UNKNOWN",
                authenticated ? "AUTHENTICATED" : "UNEXPECTED_RESPONSE", at, status, null, identity);
    }

    private static String uuid(JsonNode value) {
        if (!value.isTextual() || !UUID.matcher(value.asText()).matches()) return null;
        return value.asText().toLowerCase(Locale.ROOT);
    }

    private static CredentialValidationResult metadataResult(HttpResponse response, Instant at) {
        int status = response.getCode();
        if (status == 429) {
            return new CredentialValidationResult(
                    "UNKNOWN", "RATE_LIMITED", at, status, retryAt(response, at));
        }
        if (status >= 500) {
            return new CredentialValidationResult("UNKNOWN", "PROVIDER_UNAVAILABLE", at, status,
                    header(response, "Retry-After").isBlank() ? null : retryAt(response, at));
        }
        if (status == 403 || status == 404) return result("UNKNOWN", "ACCESS_LIMITED", at, status);
        if (status != 200 && status != 401) return result("UNKNOWN", "UNEXPECTED_RESPONSE", at, status);
        return null;
    }

    private static CredentialValidationResult result(
            String result, String reason, Instant at, int status) {
        return new CredentialValidationResult(result, reason, at, status, null);
    }

    private static String header(HttpResponse response, String name) {
        var value = response.getFirstHeader(name);
        return value == null ? "" : value.getValue();
    }

    private static Instant retryAt(HttpResponse response, Instant at) {
        String value = header(response, "Retry-After");
        try {
            return at.plusSeconds(Math.max(1, Long.parseLong(value)));
        } catch (RuntimeException ignored) {
            try {
                Instant retry = ZonedDateTime.parse(value, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
                return retry.isAfter(at) ? retry : at.plusSeconds(1);
            } catch (RuntimeException ignoredDate) {
                return at.plusSeconds(60);
            }
        }
    }
}
