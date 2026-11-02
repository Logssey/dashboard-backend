package com.logssey.secretworker.validation;

import static org.assertj.core.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.*;

import java.net.*;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.concurrent.atomic.*;

/** Notion's self endpoint is mimicked locally. Token values are synthetic. */
@ExtendWith(OutputCaptureExtension.class)
class NotionTokenValidatorTest {
    private static final String TOKEN = "ntn_" + "12345678901" + "SENTINEL".repeat(4) + "ABC";
    private static final String LEGACY = "secret_" + "SENTINEL".repeat(5) + "ABC";
    private HttpServer server;
    private int status = 200;
    private String body = "{\"object\":\"user\",\"id\":\"bot-0001\",\"type\":\"bot\",\"name\":\"sentinel-bot\"}";
    private String retry;
    private long delay;
    private final AtomicInteger calls = new AtomicInteger();
    private final AtomicReference<String> authorization = new AtomicReference<>();
    private final AtomicReference<String> version = new AtomicReference<>();

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor());
        server.createContext("/", exchange -> {
            calls.incrementAndGet();
            assertThat(exchange.getRequestURI().getPath()).isEqualTo("/v1/users/me");
            assertThat(exchange.getRequestMethod()).isEqualTo("GET");
            authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            version.set(exchange.getRequestHeaders().getFirst("Notion-Version"));
            if (retry != null) exchange.getResponseHeaders().set("Retry-After", retry);
            try {
                if (delay > 0) Thread.sleep(delay);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
            byte[] response = body.getBytes(StandardCharsets.UTF_8);
            try {
                exchange.sendResponseHeaders(status, response.length);
                exchange.getResponseBody().write(response);
            } catch (java.io.IOException ignored) {
                /* cancellation */
            } finally {
                exchange.close();
            }
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private NotionTokenValidator validator(boolean enabled, Duration timeout) {
        return new NotionTokenValidator(enabled,
                URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/v1/users/me"), timeout);
    }

    @Test
    void selfLookupIsValidAndSendsOnlyTheTokenAndVersion(CapturedOutput output) {
        var result = validator(true, Duration.ofSeconds(2)).validate(TOKEN);
        assertThat(result.result()).isEqualTo("VALID");
        assertThat(result.reasonCode()).isEqualTo("AUTHENTICATED");
        assertThat(result.httpStatus()).isEqualTo(200);
        assertThat(result.providerCheckedAt()).isNotNull();
        assertThat(authorization.get()).isEqualTo("Bearer " + TOKEN);
        assertThat(version.get()).isEqualTo(NotionTokenValidator.API_VERSION);
        assertThat(result.toString()).doesNotContain(TOKEN).doesNotContain("sentinel-bot");
        assertThat(output.getAll()).doesNotContain(TOKEN);
    }

    @Test
    void legacySecretPrefixIsAlsoSupported() {
        assertThat(validator(true, Duration.ofSeconds(2)).validate(LEGACY).result()).isEqualTo("VALID");
    }

    @Test
    void explicitUnauthorizedIsInvalidWithoutGuessingExpiryOrRevocation() {
        status = 401;
        body = "{\"object\":\"error\",\"status\":401,\"code\":\"unauthorized\",\"message\":\"API token is invalid.\"}";
        var result = validator(true, Duration.ofSeconds(2)).validate(TOKEN);
        assertThat(result.result()).isEqualTo("INVALID");
        assertThat(result.reasonCode()).isEqualTo("AUTHENTICATION_REJECTED");
    }

    @Test
    void unexplained401IsUnknownNotInvalid() {
        status = 401;
        body = "{\"object\":\"error\",\"status\":401,\"code\":\"something_else\"}";
        assertThat(validator(true, Duration.ofSeconds(2)).validate(TOKEN).result()).isEqualTo("UNKNOWN");
    }

    @Test
    void forbiddenIsNeverTreatedAsAnInvalidToken() {
        status = 403;
        body = "{\"object\":\"error\",\"status\":403,\"code\":\"restricted_resource\"}";
        var result = validator(true, Duration.ofSeconds(2)).validate(TOKEN);
        assertThat(result.result()).isEqualTo("UNKNOWN");
        assertThat(result.reasonCode()).isEqualTo("ACCESS_LIMITED");
    }

    @Test
    void rateLimitIsRetryableWithProviderDelay() {
        status = 429;
        retry = "30";
        body = "{\"object\":\"error\",\"status\":429,\"code\":\"rate_limited\"}";
        var result = validator(true, Duration.ofSeconds(2)).validate(TOKEN);
        assertThat(result.result()).isEqualTo("UNKNOWN");
        assertThat(result.reasonCode()).isEqualTo("RATE_LIMITED");
        assertThat(result.retryable()).isTrue();
        assertThat(result.nextDueAt()).isAfter(result.providerCheckedAt().plusSeconds(29));
        assertThat(calls).hasValue(1);
    }

    @Test
    void providerOutageIsRetryableUnknown() {
        status = 503;
        body = "{}";
        var result = validator(true, Duration.ofSeconds(2)).validate(TOKEN);
        assertThat(result.reasonCode()).isEqualTo("PROVIDER_UNAVAILABLE");
        assertThat(result.retryable()).isTrue();
    }

    @Test
    void successWithoutAUserObjectIsNotValid() {
        body = "{\"object\":\"list\"}";
        assertThat(validator(true, Duration.ofSeconds(2)).validate(TOKEN).reasonCode())
                .isEqualTo("UNEXPECTED_RESPONSE");
    }

    @Test
    void timeoutIsRetryableUnknown() {
        delay = 1_500;
        var result = validator(true, Duration.ofMillis(200)).validate(TOKEN);
        assertThat(result.result()).isEqualTo("UNKNOWN");
        assertThat(result.retryable()).isTrue();
    }

    @Test
    void disabledOrMalformedTokensNeverLeaveTheWorker() {
        assertThat(validator(false, Duration.ofSeconds(2)).validate(TOKEN).reasonCode()).isEqualTo("DISABLED");
        assertThat(validator(true, Duration.ofSeconds(2)).validate("ntn_short").reasonCode())
                .isEqualTo("INCOMPLETE_COMPONENTS");
        assertThat(validator(true, Duration.ofSeconds(2)).validate(TOKEN + "\r\nX-Injected: 1").reasonCode())
                .isEqualTo("INCOMPLETE_COMPONENTS");
        assertThat(calls).hasValue(0);
    }

    @Test
    void onlyTheRegisteredEndpointCanBeUsed() {
        assertThatThrownBy(() -> new NotionTokenValidator(true, URI.create("https://evil.example/v1/users/me"),
                Duration.ofSeconds(1))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new NotionTokenValidator(true, URI.create("http://127.0.0.1:1/v1/users"),
                Duration.ofSeconds(1))).isInstanceOf(IllegalArgumentException.class);
    }
}
