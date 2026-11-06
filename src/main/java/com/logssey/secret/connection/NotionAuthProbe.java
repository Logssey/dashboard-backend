package com.logssey.secret.connection;

import com.logssey.secret.notion.SecretNotionSourceCredentials;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.util.Timeout;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

/** Authentication-only check for the configured collection connection. */
@Component
class NotionAuthProbe {
    private static final String ENDPOINT = "https://api.notion.com/v1/users/me";
    private static final String UUID = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}";
    private static final int MAX_BYTES = 65_536;
    private final boolean enabled;
    private final Path tokenFile;
    private final URI endpoint;
    private final Duration timeout;

    @Autowired
    NotionAuthProbe(
            @Value("${logssey.secret.notion.collection.enabled:false}") boolean enabled,
            @Value("${logssey.secret.notion.token-file:}") String tokenFile) {
        this(enabled, configuredPath(tokenFile),
                URI.create(ENDPOINT), Duration.ofSeconds(8));
    }

    NotionAuthProbe(boolean enabled, Path tokenFile, URI endpoint, Duration timeout) {
        if (!(ENDPOINT.equals(endpoint.toString())
                || "http".equals(endpoint.getScheme()) && "127.0.0.1".equals(endpoint.getHost())
                    && "/v1/users/me".equals(endpoint.getPath()) && endpoint.getQuery() == null
                    && endpoint.getFragment() == null))
            throw new IllegalArgumentException("UNREGISTERED_NOTION_PROBE_ENDPOINT");
        this.enabled = enabled;
        this.tokenFile = tokenFile;
        this.endpoint = endpoint;
        this.timeout = timeout;
    }

    ConnectionProbeResult probe(String reference) {
        if (!SecretNotionSourceCredentials.isReference(reference))
            return ConnectionProbeResult.failed("INVALID_APPROVED_SCOPE");
        if (!enabled || tokenFile == null || wireLoggingEnabled())
            return ConnectionProbeResult.unavailable("NOTION_COLLECTION_DISABLED");
        String token;
        try {
            token = SecretNotionSourceCredentials.file(tokenFile).token();
        } catch (RuntimeException ignored) {
            return ConnectionProbeResult.unavailable("NOTION_CREDENTIALS_UNAVAILABLE");
        }
        var request = new HttpGet(endpoint);
        request.setHeader("Authorization", "Bearer " + token);
        request.setHeader("Notion-Version", "2026-03-11");
        request.setHeader("Accept", "application/json");
        request.setHeader("User-Agent", "logssey-secret-connection-test");
        var manager = PoolingHttpClientConnectionManagerBuilder.create()
                .setDefaultConnectionConfig(ConnectionConfig.custom()
                        .setConnectTimeout(Timeout.ofSeconds(3)).build()).build();
        var http = HttpClients.custom().setConnectionManager(manager)
                .setDefaultRequestConfig(RequestConfig.custom()
                        .setConnectionRequestTimeout(Timeout.ofSeconds(3))
                        .setResponseTimeout(Timeout.ofMilliseconds(timeout.toMillis())).build())
                .disableAutomaticRetries().disableRedirectHandling().disableCookieManagement()
                .disableAuthCaching().disableContentCompression().build();
        var executor = Executors.newVirtualThreadPerTaskExecutor();
        Future<ConnectionProbeResult> pending = null;
        try {
            pending = executor.submit(() -> {
                var response = http.executeOpen(null, request, null);
                try {
                    int status = response.getCode();
                    if (status == 401 || status == 403 || status == 404)
                        return ConnectionProbeResult.failed("NOTION_ACCESS_DENIED");
                    if (status == 429 || status == 529)
                        return ConnectionProbeResult.unavailable("NOTION_RATE_LIMITED");
                    if (status != 200) return ConnectionProbeResult.unavailable("NOTION_UNAVAILABLE");
                    byte[] body = response.getEntity() == null ? new byte[0]
                            : response.getEntity().getContent().readNBytes(MAX_BYTES + 1);
                    try {
                        if (body.length > MAX_BYTES)
                            return ConnectionProbeResult.unavailable("NOTION_UNAVAILABLE");
                        var root = new JsonMapper().readTree(body);
                        boolean valid = root != null && root.isObject()
                                && "user".equals(root.path("object").asText(""))
                                && root.path("id").isTextual()
                                && root.path("id").asText().matches(UUID)
                                && java.util.Set.of("bot", "person").contains(root.path("type").asText(""));
                        return valid ? ConnectionProbeResult.connected()
                                : ConnectionProbeResult.unavailable("NOTION_UNAVAILABLE");
                    } finally {
                        Arrays.fill(body, (byte) 0);
                    }
                } finally {
                    request.cancel();
                    try { response.close(); } catch (java.io.IOException ignored) { }
                }
            });
            return pending.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
            return ConnectionProbeResult.unavailable("NOTION_UNAVAILABLE");
        } catch (ExecutionException | TimeoutException | RuntimeException ignored) {
            return ConnectionProbeResult.unavailable("NOTION_UNAVAILABLE");
        } finally {
            request.cancel();
            if (pending != null && !pending.isDone()) pending.cancel(true);
            http.close(CloseMode.IMMEDIATE);
            executor.shutdownNow();
        }
    }

    private static boolean wireLoggingEnabled() {
        return !System.getProperty("jdk.httpclient.HttpClient.log", "").isBlank()
                || LoggerFactory.getLogger("org.apache.hc.client5.http").isDebugEnabled()
                || LoggerFactory.getLogger("org.apache.hc.client5.http.headers").isDebugEnabled()
                || LoggerFactory.getLogger("org.apache.hc.client5.http.wire").isDebugEnabled();
    }

    private static Path configuredPath(String value) {
        try { return value == null || value.isBlank() ? null : Path.of(value); }
        catch (java.nio.file.InvalidPathException ignored) { return null; }
    }
}
