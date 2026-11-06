package com.logssey.secretworker.validation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

@ExtendWith(OutputCaptureExtension.class)
class NotionTokenValidatorTest {
    private static final String CURRENT = "ntn_" + "SENTINEL".repeat(5) + "ABCDEF";
    private static final String LEGACY = "secret_" + "SENTINEL".repeat(5) + "ABC";
    private static final String BOT_ID = "3c90c3cc-0d44-4b50-8888-8dd25736052a";
    private static final String WORKSPACE_ID = "b55c9c91-384d-452b-81db-d1ef79372b75";
    private static final String USER_BODY = "{\"object\":\"user\",\"type\":\"bot\",\"id\":\""
            + BOT_ID + "\",\"name\":\"PRIVATE_NAME_SENTINEL\",\"bot\":{\"workspace_id\":\""
            + WORKSPACE_ID + "\",\"workspace_name\":\"PRIVATE_WORKSPACE_SENTINEL\","
            + "\"owner\":{\"type\":\"workspace\"}}}";

    private HttpServer server;
    private ExecutorService serverExecutor;
    private volatile int status = 200;
    private volatile String body = USER_BODY;
    private volatile String retryAfter;
    private volatile String redirect;
    private volatile long headerDelay;
    private volatile long byteDelay;
    private volatile boolean disconnect;
    private final AtomicInteger calls = new AtomicInteger();
    private final AtomicReference<String> authorization = new AtomicReference<>();

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        serverExecutor = Executors.newVirtualThreadPerTaskExecutor();
        server.setExecutor(serverExecutor);
        server.createContext("/", exchange -> {
            calls.incrementAndGet();
            assertThat(exchange.getRequestURI().getPath()).isEqualTo("/v1/users/me");
            assertThat(exchange.getRequestMethod()).isEqualTo("GET");
            assertThat(exchange.getRequestHeaders().getFirst("Notion-Version"))
                    .isEqualTo("2026-03-11");
            authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            if (retryAfter != null) exchange.getResponseHeaders().set("Retry-After", retryAfter);
            if (redirect != null) exchange.getResponseHeaders().set("Location", redirect);
            if (disconnect) {
                exchange.close();
                return;
            }
            try {
                if (headerDelay > 0) Thread.sleep(headerDelay);
                byte[] response = body.getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(status, response.length);
                if (byteDelay == 0) {
                    exchange.getResponseBody().write(response);
                } else {
                    for (byte value : response) {
                        exchange.getResponseBody().write(value);
                        exchange.getResponseBody().flush();
                        Thread.sleep(byteDelay);
                    }
                }
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            } catch (java.io.IOException ignored) {
                // A bounded client can cancel the mock's delayed response.
            } finally {
                exchange.close();
            }
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
        serverExecutor.shutdownNow();
    }

    private NotionTokenValidator validator(boolean enabled, Duration timeout) {
        return new NotionTokenValidator(enabled,
                URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/v1/users/me"),
                timeout);
    }

    private CredentialValidationResult validate() {
        return validator(true, Duration.ofSeconds(2)).validate(CURRENT);
    }

    @Test
    void authenticatesCurrentAndLegacyTokensWithoutRetainingNames(CapturedOutput output) {
        for (String token : new String[] {CURRENT, LEGACY}) {
            var result = validator(true, Duration.ofSeconds(2)).validate(token);
            assertThat(result.result()).isEqualTo("VALID");
            assertThat(result.reasonCode()).isEqualTo("AUTHENTICATED");
            assertThat(result.httpStatus()).isEqualTo(200);
            assertThat(result.providerCheckedAt()).isNotNull();
            assertThat(authorization).hasValue("Bearer " + token);
            assertThat(result.identity()).isNotNull();
            assertThat(result.identity().provider()).isEqualTo("NOTION");
            assertThat(result.identity().principalId()).isEqualTo(BOT_ID);
            assertThat(result.identity().claims()).containsExactlyInAnyOrderEntriesOf(
                    Map.of("schemaVersion", 1, "workspaceRef", WORKSPACE_ID, "ownerType", "workspace"));
            assertThat(result.toString())
                    .doesNotContain(CURRENT, LEGACY, "PRIVATE_NAME_SENTINEL", "PRIVATE_WORKSPACE_SENTINEL");
        }
        assertThat(output.getAll())
                .doesNotContain(CURRENT, LEGACY, "PRIVATE_NAME_SENTINEL", "PRIVATE_WORKSPACE_SENTINEL");
        assertThat(calls).hasValue(2);
    }

    @Test
    void personalOwnersDoNotRevealTheirUserDetails() {
        body = "{\"object\":\"user\",\"type\":\"bot\",\"id\":\"" + BOT_ID
                + "\",\"bot\":{\"owner\":{\"type\":\"user\",\"user\":{"
                + "\"name\":\"PRIVATE_OWNER_SENTINEL\",\"person\":{\"email\":\"private@example.invalid\"}}}}}";
        var result = validate();
        assertThat(result.result()).isEqualTo("VALID");
        assertThat(result.identity().claims())
                .containsExactlyInAnyOrderEntriesOf(Map.of("schemaVersion", 1, "ownerType", "user"));
        assertThat(result.toString()).doesNotContain("PRIVATE_OWNER_SENTINEL", "private@example.invalid");
    }

    @Test
    void optionalMetadataDoesNotChangeAuthenticationSuccess() {
        body = "{\"object\":\"user\",\"type\":\"bot\",\"id\":\"" + BOT_ID
                + "\",\"bot\":{\"workspace_id\":\"not-a-uuid\",\"owner\":{\"type\":\"unexpected\"}}}";
        var result = validate();
        assertThat(result.result()).isEqualTo("VALID");
        assertThat(result.identity().claims()).containsExactlyInAnyOrderEntriesOf(Map.of("schemaVersion", 1));
        body = "{\"object\":\"user\",\"type\":\"person\",\"id\":\"" + BOT_ID + "\"}";
        result = validate();
        assertThat(result.result()).isEqualTo("VALID");
        assertThat(result.identity()).isNull();
    }

    @Test
    void requiresAStructurallyValidAuthenticatedUser() {
        for (String value : new String[] {
                "{}", "null", "[]", "not-json",
                "{\"object\":\"user\",\"type\":\"bot\",\"id\":123}",
                "{\"object\":\"user\",\"type\":\"bot\",\"id\":\"1-1-1-1-1\"}",
                "{\"object\":\"error\",\"type\":\"bot\",\"id\":\"" + BOT_ID + "\"}",
                "{\"object\":\"user\",\"id\":\"" + BOT_ID + "\"}",
                "{\"object\":\"user\",\"type\":\"unknown\",\"id\":\"" + BOT_ID + "\"}"
        }) {
            body = value;
            var result = validate();
            assertThat(result.result()).isEqualTo("UNKNOWN");
            assertThat(result.identity()).isNull();
        }
    }

    @Test
    void onlyExplicitAuthenticationRejectionIsInvalid() {
        status = 401;
        body = "{\"object\":\"error\",\"code\":\"unauthorized\",\"message\":\"PRIVATE_MESSAGE_SENTINEL\"}";
        var result = validate();
        assertThat(result.result()).isEqualTo("INVALID");
        assertThat(result.reasonCode()).isEqualTo("AUTHENTICATION_REJECTED");
        assertThat(result.identity()).isNull();
        assertThat(result.toString()).doesNotContain("PRIVATE_MESSAGE_SENTINEL", "REVOKED", "EXPIRED");
        for (String value : new String[] {"{}", "null", "not-json", "{\"code\":\"invalid_client\"}"}) {
            body = value;
            assertThat(validate().result()).isEqualTo("UNKNOWN");
        }
    }

    @Test
    void accessRestrictionsAndRequestErrorsRemainUnknown() {
        for (int code : new int[] {400, 403, 404}) {
            status = code;
            var result = validate();
            assertThat(result.result()).isEqualTo("UNKNOWN");
            assertThat(result.reasonCode())
                    .isEqualTo(code == 400 ? "UNEXPECTED_RESPONSE" : "ACCESS_LIMITED");
            assertThat(result.httpStatus()).isEqualTo(code);
        }
    }

    @Test
    void preservesLongAndDateRetryAfterValues() {
        status = 429;
        body = "{\"code\":\"rate_limited\"}";
        retryAfter = "1800";
        var result = validate();
        assertThat(result.reasonCode()).isEqualTo("RATE_LIMITED");
        assertThat(result.retryable()).isTrue();
        assertThat(result.nextDueAt()).isAfter(Instant.now().plusSeconds(1790));
        retryAfter = ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(40)
                .format(DateTimeFormatter.RFC_1123_DATE_TIME);
        assertThat(validate().nextDueAt()).isAfter(Instant.now().plusSeconds(2390));
        for (String value : new String[] {"unparseable", "999999999999999999999999999999", ""}) {
            retryAfter = value;
            assertThat(validate().nextDueAt()).isAfter(Instant.now().plusSeconds(50));
        }
    }

    @Test
    void accessBlockedIsUnknownAndDoesNotRetry() {
        status = 429;
        retryAfter = "1800";
        body = "{\"object\":\"error\",\"code\":\"rate_limited\",\"additional_data\":"
                + "{\"rate_limit_reason\":\"public_api_request_blocked\"}}";
        var result = validate();
        assertThat(result.result()).isEqualTo("UNKNOWN");
        assertThat(result.reasonCode()).isEqualTo("PROVIDER_ACCESS_BLOCKED");
        assertThat(result.nextDueAt()).isNull();
        assertThat(result.retryable()).isFalse();
    }

    @Test
    void malformedOrOversizedRateLimitBodiesPreserveTheObservedWait() {
        status = 429;
        retryAfter = "1800";
        for (String value : new String[] {"not-json", "null", "x".repeat(65_537)}) {
            body = value;
            var result = validate();
            assertThat(result.reasonCode()).isEqualTo("RATE_LIMITED");
            assertThat(result.nextDueAt()).isAfter(Instant.now().plusSeconds(1790));
        }
    }

    @Test
    void serverFailuresIncluding529PreserveCooldownWithoutConsumingBodies() {
        retryAfter = "1800";
        byteDelay = 1000;
        for (int code : new int[] {500, 502, 503, 504, 529}) {
            status = code;
            var result = validate();
            assertThat(result.result()).isEqualTo("UNKNOWN");
            assertThat(result.reasonCode()).isEqualTo("PROVIDER_UNAVAILABLE");
            assertThat(result.nextDueAt()).isAfter(Instant.now().plusSeconds(1790));
            assertThat(result.retryable()).isTrue();
        }
    }

    @Test
    void aRateLimitHeaderSurvivesAStalledBody() {
        status = 429;
        retryAfter = "1800";
        body = "slow body";
        byteDelay = 1000;
        long start = System.nanoTime();
        var result = validator(true, Duration.ofMillis(500)).validate(CURRENT);
        assertThat(result.reasonCode()).isEqualTo("RATE_LIMITED");
        assertThat(result.nextDueAt()).isAfter(Instant.now().plusSeconds(1790));
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(3));
        assertThat(calls).hasValue(1);
    }

    @Test
    void anEofSendsOnlyOneWireRequestForEachTokenShape() {
        disconnect = true;
        for (String token : new String[] {CURRENT, LEGACY}) {
            calls.set(0);
            var result = validator(true, Duration.ofSeconds(2)).validate(token);
            assertThat(result.result()).isEqualTo("UNKNOWN");
            assertThat(result.reasonCode()).isEqualTo("CLIENT_FAILURE");
            assertThat(calls).hasValue(1);
        }
    }

    @Test
    void theOverallDeadlineBoundsDelayedHeadersAndBodies() {
        for (boolean slowBody : new boolean[] {false, true}) {
            headerDelay = slowBody ? 0 : 1000;
            byteDelay = slowBody ? 50 : 0;
            long start = System.nanoTime();
            var result = validator(true, Duration.ofMillis(300)).validate(CURRENT);
            assertThat(result.result()).isEqualTo("UNKNOWN");
            assertThat(result.providerCheckedAt()).isNull();
            assertThat(result.identity()).isNull();
            assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(3));
        }
    }

    @Test
    void oversizedBodiesCannotCreateAuthenticationEvidence() {
        body = "x".repeat(65_537);
        var result = validate();
        assertThat(result.result()).isEqualTo("UNKNOWN");
        assertThat(result.reasonCode()).isEqualTo("UNEXPECTED_RESPONSE");
        assertThat(result.identity()).isNull();
    }

    @Test
    void redirectsAreNeverFollowed() {
        status = 302;
        redirect = "http://127.0.0.1:" + server.getAddress().getPort() + "/token-destination";
        assertThat(validate().result()).isEqualTo("UNKNOWN");
        assertThat(calls).hasValue(1);
    }

    @Test
    void disabledAndUnsupportedInputsDoNotSendRequests() {
        assertThat(validator(false, Duration.ofSeconds(2)).validate(CURRENT).result()).isEqualTo("UNCHECKED");
        for (String token : new String[] {null, "", "ntn_short", CURRENT + "\r\nInjected: secret", LEGACY + "x"}) {
            assertThat(validator(true, Duration.ofSeconds(2)).validate(token).result()).isEqualTo("UNCHECKED");
        }
        assertThat(calls).hasValue(0);
    }

    @Test
    void diagnosticLoggingFailsClosedBeforeSendingTokens() {
        for (String name : new String[] {"org.apache.hc.client5.http", "org.apache.hc.client5.http.headers", "org.apache.hc.client5.http.wire"}) {
            var logger = (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(name);
            var previous = logger.getLevel();
            try {
                logger.setLevel(ch.qos.logback.classic.Level.DEBUG);
                assertThat(validate().result()).isEqualTo("UNCHECKED");
                assertThat(calls).hasValue(0);
            } finally {
                logger.setLevel(previous);
            }
        }
        String previous = System.getProperty("jdk.httpclient.HttpClient.log");
        try {
            System.setProperty("jdk.httpclient.HttpClient.log", "headers");
            assertThat(validate().result()).isEqualTo("UNCHECKED");
            assertThat(calls).hasValue(0);
        } finally {
            if (previous == null) System.clearProperty("jdk.httpclient.HttpClient.log");
            else System.setProperty("jdk.httpclient.HttpClient.log", previous);
        }
    }

    @Test
    void arbitraryEndpointsAreRejected() {
        for (String value : new String[] {
                "https://example.invalid/v1/users/me", "https://api.notion.com/v1/users/me?token=other",
                "http://127.0.0.1:1/other", "http://user@127.0.0.1:1/v1/users/me"
        }) {
            assertThatThrownBy(() -> new NotionTokenValidator(true, URI.create(value), Duration.ofSeconds(2)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("UNREGISTERED_VALIDATION_ENDPOINT");
        }
    }
}
