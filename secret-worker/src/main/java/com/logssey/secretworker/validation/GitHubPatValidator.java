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

/** A discovered PAT authenticates only against the fixed registered /user endpoint. */
@Component
public final class GitHubPatValidator {
    public static final String METHOD = "GITHUB_GET_AUTHENTICATED_USER";
    public static final String VERSION = "1";
    public static final String API_VERSION = "2026-03-10";
    private static final int MAX_BYTES = 65_536;
    private final boolean enabled;
    private final URI endpoint;
    private final HttpClient http;
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
        this.http =
                !System.getProperty("jdk.httpclient.HttpClient.log", "").isBlank()
                        ? null
                        : HttpClient.newBuilder()
                                .followRedirects(HttpClient.Redirect.NEVER)
                                .connectTimeout(Duration.ofSeconds(3))
                                .build();
    }

    public boolean enabled() {
        return enabled
                && http != null
                && System.getProperty("jdk.httpclient.HttpClient.log", "").isBlank();
    }

    public CredentialValidationResult validate(String token) {
        if (!enabled()) return CredentialValidationResult.unchecked("DISABLED");
        if (token == null
                || !(token.matches("ghp_[A-Za-z0-9_]{36}")
                        || token.matches("github_pat_[A-Za-z0-9_]{70,}")))
            return CredentialValidationResult.unchecked("INCOMPLETE_COMPONENTS");
        CompletableFuture<HttpResponse<byte[]>> pending = null;
        try {
            var request =
                    HttpRequest.newBuilder(endpoint)
                            .timeout(timeout)
                            .GET()
                            .header("Authorization", "Bearer " + token)
                            .header("Accept", "application/vnd.github+json")
                            .header("User-Agent", "logssey-secret-worker")
                            .header("X-GitHub-Api-Version", API_VERSION)
                            .build();
            pending = http.sendAsync(request, ignored -> new LimitedBody());
            var response = pending.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
            var at = Instant.now();
            int status = response.statusCode();
            byte[] body = response.body();
            try {
                if (status == 429
                        || status == 403
                                && response.headers()
                                        .firstValue("X-RateLimit-Remaining")
                                        .orElse("")
                                        .equals("0")
                        || status == 403
                                && response.headers().firstValue("Retry-After").isPresent())
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
                    // No inference about expiry or revocation: this is only explicit authentication
                    // rejection.
                    return result(
                            "Bad credentials".equals(root.path("message").asText(""))
                                    ? "INVALID"
                                    : "UNKNOWN",
                            "Bad credentials".equals(root.path("message").asText(""))
                                    ? "AUTHENTICATION_REJECTED"
                                    : "UNEXPECTED_RESPONSE",
                            at,
                            status);
                }
                boolean principal =
                        root != null
                                && root.isObject()
                                && root.path("id").isIntegralNumber()
                                && root.path("id").asLong(0) > 0
                                && root.path("login").isTextual()
                                && !root.path("login").asText("").isBlank();
                return new CredentialValidationResult(principal ? "VALID" : "UNKNOWN",
                        principal ? "AUTHENTICATED" : "UNEXPECTED_RESPONSE",at,status,null,
                        principal?com.logssey.secret.permission.core.SecretProviderIdentity.github(root.path("id").asLong(),token.startsWith("ghp_"),response.headers().firstValue("X-OAuth-Scopes").orElse(null)):null);
            } finally {
                Arrays.fill(body, (byte) 0);
            }
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
            return CredentialValidationResult.unknown("CLIENT_FAILURE");
        } catch (TimeoutException ignored) {
            return CredentialValidationResult.unknown("PROVIDER_UNAVAILABLE");
        } catch (ExecutionException | RuntimeException ignored) {
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
            seconds = Long.parseLong(value);
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
