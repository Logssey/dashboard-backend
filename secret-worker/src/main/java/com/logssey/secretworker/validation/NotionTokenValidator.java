package com.logssey.secretworker.validation;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.*;
import java.nio.ByteBuffer;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.Flow;

/**
 * A discovered Notion token authenticates only against the fixed registered self endpoint
 * (GET /v1/users/me). It reads no page, database or user list. Same safety contract as
 * {@link GitHubPatValidator}: no body, header or exception text leaves this class.
 */
@Component
public final class NotionTokenValidator {
    public static final String METHOD = "NOTION_GET_SELF";
    public static final String VERSION = "1";
    public static final String ENDPOINT_CLASS = "NOTION_SELF";
    public static final String API_VERSION = "2026-03-11";
    private static final String OFFICIAL = "https://api.notion.com/v1/users/me";
    private static final int MAX_BYTES = 65_536;
    private final boolean enabled;
    private final URI endpoint;
    private final HttpClient http;
    private final Duration timeout;
    private final JsonMapper json = new JsonMapper();

    @org.springframework.beans.factory.annotation.Autowired
    public NotionTokenValidator(
            @Value("${logssey.secret.validation.notion.enabled:false}") boolean enabled) {
        this(enabled, URI.create(OFFICIAL), Duration.ofSeconds(8));
    }

    // Package-private test seam; never sourced from a connection, finding, URL or API request.
    NotionTokenValidator(boolean enabled, URI endpoint, Duration timeout) {
        if (!(OFFICIAL.equals(endpoint.toString())
                || "http".equals(endpoint.getScheme())
                        && "127.0.0.1".equals(endpoint.getHost())
                        && "/v1/users/me".equals(endpoint.getPath())
                        && endpoint.getQuery() == null
                        && endpoint.getFragment() == null))
            throw new IllegalArgumentException("UNREGISTERED_VALIDATION_ENDPOINT");
        this.enabled = enabled;
        this.endpoint = endpoint;
        this.timeout = timeout;
        this.http =
                !System.getProperty("jdk.httpclient.HttpClient.log", "").isBlank()
                        ? null
                        : HttpClient.newBuilder()
                                .version(HttpClient.Version.HTTP_1_1)
                                .followRedirects(HttpClient.Redirect.NEVER)
                                .connectTimeout(Duration.ofSeconds(5))
                                .build();
    }

    public boolean enabled() {
        return enabled
                && http != null
                && System.getProperty("jdk.httpclient.HttpClient.log", "").isBlank();
    }

    /** Current ntn_ connection tokens (the normalizer's shape) and legacy secret_ tokens only. */
    static boolean supportedShape(String token) {
        return token != null
                && (token.matches("ntn_[A-Za-z0-9_]{46}") || token.matches("secret_[A-Za-z0-9]{43}"));
    }

    public CredentialValidationResult validate(String token) {
        if (!enabled()) return CredentialValidationResult.unchecked("DISABLED");
        if (!supportedShape(token)) return CredentialValidationResult.unchecked("INCOMPLETE_COMPONENTS");
        CompletableFuture<HttpResponse<byte[]>> pending = null;
        try {
            var request =
                    HttpRequest.newBuilder(endpoint)
                            .timeout(timeout)
                            .GET()
                            .header("Authorization", "Bearer " + token)
                            .header("Notion-Version", API_VERSION)
                            .header("User-Agent", "logssey-secret-worker")
                            .build();
            pending = http.sendAsync(request, ignored -> new LimitedBody());
            var response = pending.get(timeout.toMillis() + 1_000, TimeUnit.MILLISECONDS);
            var at = Instant.now();
            int status = response.statusCode();
            byte[] body = response.body();
            try {
                if (status == 429)
                    return new CredentialValidationResult(
                            "UNKNOWN", "RATE_LIMITED", at, status, retryAt(response, at));
                if (status >= 500)
                    return new CredentialValidationResult(
                            "UNKNOWN",
                            "PROVIDER_UNAVAILABLE",
                            at,
                            status,
                            response.headers().firstValue("Retry-After").isPresent()
                                    ? retryAt(response, at)
                                    : null);
                // Permission or page restrictions are never treated as an invalid token.
                if (status == 403 || status == 404)
                    return result("UNKNOWN", "ACCESS_LIMITED", at, status);
                if (status != 200 && status != 401)
                    return result("UNKNOWN", "UNEXPECTED_RESPONSE", at, status);
                JsonNode root;
                try {
                    root = json.readTree(body);
                } catch (RuntimeException ignored) {
                    return result("UNKNOWN", "UNEXPECTED_RESPONSE", at, status);
                }
                if (status == 401) {
                    // Only Notion's explicit "unauthorized" code is a rejection. Expiry or
                    // revocation is never inferred from it.
                    boolean rejected = "unauthorized".equals(root.path("code").asText(""));
                    return result(
                            rejected ? "INVALID" : "UNKNOWN",
                            rejected ? "AUTHENTICATION_REJECTED" : "UNEXPECTED_RESPONSE",
                            at,
                            status);
                }
                boolean principal =
                        root != null
                                && root.isObject()
                                && "user".equals(root.path("object").asText(""))
                                && root.path("id").isTextual()
                                && !root.path("id").asText("").isBlank();
                return result(principal ? "VALID" : "UNKNOWN",
                        principal ? "AUTHENTICATED" : "UNEXPECTED_RESPONSE", at, status);
            } finally {
                Arrays.fill(body, (byte) 0);
            }
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
            return CredentialValidationResult.unknown("CLIENT_FAILURE");
        } catch (TimeoutException ignored) {
            return CredentialValidationResult.unknown("PROVIDER_UNAVAILABLE");
        } catch (ExecutionException ignored) {
            // HttpTimeoutException, connection failures and body limits arrive here.
            return CredentialValidationResult.unknown("PROVIDER_UNAVAILABLE");
        } catch (RuntimeException ignored) {
            return CredentialValidationResult.unknown("CLIENT_FAILURE");
        } finally {
            if (pending != null && !pending.isDone()) pending.cancel(true);
        }
    }

    private static CredentialValidationResult result(
            String result, String reason, Instant at, int status) {
        return new CredentialValidationResult(result, reason, at, status, null);
    }

    private static Instant retryAt(HttpResponse<?> response, Instant at) {
        long seconds = 60;
        String value = response.headers().firstValue("Retry-After").orElse("");
        try {
            seconds = Long.parseLong(value.trim());
        } catch (RuntimeException ignored) {
            try {
                seconds =
                        Duration.between(
                                        at,
                                        ZonedDateTime.parse(
                                                        value, DateTimeFormatter.RFC_1123_DATE_TIME)
                                                .toInstant())
                                .getSeconds();
            } catch (RuntimeException ignoredDate) {
                /* safe bounded default */
            }
        }
        return at.plusSeconds(Math.max(1, Math.min(900, seconds)));
    }

    private static final class LimitedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final CompletableFuture<byte[]> body = new CompletableFuture<>();
        private final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        private Flow.Subscription subscription;

        @Override
        public CompletionStage<byte[]> getBody() {
            return body;
        }

        @Override
        public void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            subscription.request(1);
        }

        @Override
        public void onNext(List<ByteBuffer> buffers) {
            for (var buffer : buffers) {
                if (bytes.size() + buffer.remaining() > MAX_BYTES) {
                    subscription.cancel();
                    body.completeExceptionally(new IllegalStateException("RESPONSE_LIMIT"));
                    return;
                }
                byte[] chunk = new byte[buffer.remaining()];
                buffer.get(chunk);
                bytes.writeBytes(chunk);
                Arrays.fill(chunk, (byte) 0);
            }
            subscription.request(1);
        }

        @Override
        public void onError(Throwable ignored) {
            body.completeExceptionally(new IllegalStateException("RESPONSE_UNAVAILABLE"));
        }

        @Override
        public void onComplete() {
            body.complete(bytes.toByteArray());
        }
    }
}
