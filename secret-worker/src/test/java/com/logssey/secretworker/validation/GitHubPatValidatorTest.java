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

@ExtendWith(OutputCaptureExtension.class)
class GitHubPatValidatorTest {
    private static final String CLASSIC = "ghp_" + "SENTINEL".repeat(4) + "ABCD";
    private static final String FINE = "github_pat_" + "SENTINEL".repeat(9);
    private HttpServer server;
    private int status = 200;
    private String body = "{\"id\":123,\"login\":\"sentinel-subject\"}";
    private String retry;
    private String remaining;
    private String reset;
    private String redirect;
    private long delay;
    private long byteDelay;
    private boolean disconnect;
    private AtomicInteger calls = new AtomicInteger();
    private AtomicReference<String> authorization = new AtomicReference<>();

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor());
        server.createContext(
                "/",
                exchange -> {
                    calls.incrementAndGet();
                    assertThat(exchange.getRequestURI().getPath()).isEqualTo("/user");
                    assertThat(exchange.getRequestMethod()).isEqualTo("GET");
                    assertThat(exchange.getRequestHeaders().getFirst("X-GitHub-Api-Version"))
                            .isEqualTo("2026-03-10");
                    authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
                    if (retry != null) exchange.getResponseHeaders().set("Retry-After", retry);
                    if (remaining != null) exchange.getResponseHeaders().set("X-RateLimit-Remaining", remaining);
                    if (reset != null) exchange.getResponseHeaders().set("X-RateLimit-Reset", reset);
                    if (redirect != null) exchange.getResponseHeaders().set("Location", redirect);
                    if (disconnect) { exchange.close(); return; }
                    try {
                        if (delay > 0) Thread.sleep(delay);
                    } catch (InterruptedException ignored) {
                        Thread.currentThread().interrupt();
                    }
                    byte[] response = body.getBytes(StandardCharsets.UTF_8);
                    try {
                        exchange.sendResponseHeaders(status, response.length);
                        if (byteDelay == 0) exchange.getResponseBody().write(response);
                        else for (byte value : response) {
                            exchange.getResponseBody().write(value);
                            exchange.getResponseBody().flush();
                            try { Thread.sleep(byteDelay); }
                            catch (InterruptedException ignored) { Thread.currentThread().interrupt(); break; }
                        }
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

    private GitHubPatValidator validator(boolean enabled, Duration timeout) {
        return new GitHubPatValidator(
                enabled,
                URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/user"),
                timeout);
    }

    private CredentialValidationResult validate() {
        return validator(true, Duration.ofSeconds(2)).validate(CLASSIC);
    }

    @Test
    void authenticatesBothPatTypesUsingTheDiscoveredToken(CapturedOutput output) {
        assertThat(validate().result()).isEqualTo("VALID");
        assertThat(authorization).hasValue("Bearer " + CLASSIC);
        var fine = validator(true, Duration.ofSeconds(2)).validate(FINE);
        assertThat(fine.result()).isEqualTo("VALID");
        assertThat(authorization).hasValue("Bearer " + FINE);
        assertThat(fine.toString()).doesNotContain(CLASSIC, FINE, "sentinel-subject");
        assertThat(output.getAll()).doesNotContain(CLASSIC, FINE, "sentinel-subject");
    }

    @Test
    void onlyExplicitAuthenticationDenialIsInvalid() {
        status = 401;
        body = "{\"message\":\"Bad credentials\"}";
        assertThat(validate())
                .extracting(
                        CredentialValidationResult::result, CredentialValidationResult::reasonCode)
                .containsExactly("INVALID", "AUTHENTICATION_REJECTED");
        body = "{\"message\":\"client configuration failed\"}";
        assertThat(validate().result()).isEqualTo("UNKNOWN");
        body = "not-json";
        assertThat(validate().result()).isEqualTo("UNKNOWN");
    }

    @Test
    void limitsAndAccessFailuresNeverBecomeInvalid() {
        for (int code : new int[] {403, 404, 429, 500}) {
            status = code;
            assertThat(validate().result()).isEqualTo("UNKNOWN");
        }
        status = 403;
        retry = "120";
        var limited = validate();
        assertThat(limited.reasonCode()).isEqualTo("RATE_LIMITED");
        assertThat(limited.nextDueAt()).isAfter(Instant.now().plusSeconds(110));
    }

    @Test
    void providerWaitsArePreservedAndTheLaterRateLimitSignalWins() {
        status = 429;
        retry = "1800";
        assertThat(validate().nextDueAt()).isAfter(Instant.now().plusSeconds(1790));
        retry = ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(40)
                .format(java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME);
        assertThat(validate().nextDueAt()).isAfter(Instant.now().plusSeconds(2390));
        status = 403;
        retry = "60";
        remaining = "0";
        reset = String.valueOf(Instant.now().plusSeconds(1800).getEpochSecond());
        assertThat(validate().nextDueAt()).isAfter(Instant.now().plusSeconds(1790));
        retry = null;
        assertThat(validate().nextDueAt()).isAfter(Instant.now().plusSeconds(1790));
        reset = "unparseable";
        assertThat(validate().nextDueAt()).isAfter(Instant.now().plusSeconds(50));
    }

    @Test
    void anEofMakesOnlyOneWireRequestForEachPatType() {
        disconnect = true;
        for (String token : new String[] {CLASSIC, FINE}) {
            calls.set(0);
            var result = validator(true, Duration.ofSeconds(2)).validate(token);
            assertThat(result.result()).isEqualTo("UNKNOWN");
            assertThat(result.reasonCode()).isEqualTo("CLIENT_FAILURE");
            assertThat(calls).hasValue(1);
        }
    }

    @Test
    void theOverallDeadlineAlsoStopsASlowBody() {
        byteDelay = 30;
        long start = System.nanoTime();
        var result = validator(true, Duration.ofMillis(100)).validate(CLASSIC);
        assertThat(result.result()).isEqualTo("UNKNOWN");
        assertThat(result.providerCheckedAt()).isNull();
        assertThat(Duration.ofNanos(System.nanoTime()-start)).isLessThan(Duration.ofSeconds(2));
        assertThat(calls).hasValue(1);
    }

    @Test
    void rateLimitHeadersSurviveASlowErrorBody() {
        status = 429;
        retry = "1800";
        body = "slow error body";
        byteDelay = 1000;
        long start = System.nanoTime();
        var result = validator(true, Duration.ofMillis(200)).validate(CLASSIC);
        assertThat(result.result()).isEqualTo("UNKNOWN");
        assertThat(result.reasonCode()).isEqualTo("RATE_LIMITED");
        assertThat(result.nextDueAt()).isAfter(Instant.now().plusSeconds(1790));
        assertThat(Duration.ofNanos(System.nanoTime()-start)).isLessThan(Duration.ofSeconds(2));
        assertThat(calls).hasValue(1);
    }

    @Test
    void apacheHeaderAndWireLoggingFailClosedBeforeSendingAnyToken() {
        for (String name : new String[] {"org.apache.hc.client5.http.headers", "org.apache.hc.client5.http.wire"}) {
            var logger = (ch.qos.logback.classic.Logger)org.slf4j.LoggerFactory.getLogger(name);
            var previous = logger.getLevel();
            try {
                logger.setLevel(ch.qos.logback.classic.Level.DEBUG);
                assertThat(validator(true, Duration.ofSeconds(1)).enabled()).isFalse();
                assertThat(validate().result()).isEqualTo("UNCHECKED");
                assertThat(calls).hasValue(0);
            } finally { logger.setLevel(previous); }
        }
    }

    @Test
    void successfulStatusRequiresAnAuthenticatedPrincipal() {
        for (String value :
                new String[] {
                    "{}",
                    "{\"id\":123}",
                    "{\"id\":0,\"login\":\"x\"}",
                    "{\"id\":\"123\",\"login\":\"x\"}",
                    "{\"id\":123,\"login\":\"\"}"
                }) {
            body = value;
            assertThat(validate().result()).isEqualTo("UNKNOWN");
        }
    }

    @Test
    void redirectsAreNeverFollowed() {
        status = 302;
        redirect = "http://127.0.0.1:" + server.getAddress().getPort() + "/secret-destination";
        assertThat(validate().result()).isEqualTo("UNKNOWN");
        assertThat(calls).hasValue(1);
    }

    @Test
    void oversizedAndDelayedBodiesCannotProduceAuthenticationEvidence() {
        body = "x".repeat(65_537);
        assertThat(validate().result()).isEqualTo("UNKNOWN");
        body = "{\"id\":1,\"login\":\"x\"}";
        delay = 500;
        long start = System.nanoTime();
        var result = validator(true, Duration.ofMillis(100)).validate(CLASSIC);
        assertThat(result.result()).isEqualTo("UNKNOWN");
        assertThat(result.providerCheckedAt()).isNull();
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(2));
    }

    @Test
    void rawHttpDiagnosticModeFailsClosedBeforeSendingAnyToken() {
        String previous = System.getProperty("jdk.httpclient.HttpClient.log");
        try {
            System.setProperty("jdk.httpclient.HttpClient.log", "headers");
            assertThat(validator(true, Duration.ofSeconds(1)).enabled()).isFalse();
            assertThat(validate().result()).isEqualTo("UNCHECKED");
            assertThat(calls).hasValue(0);
        } finally {
            if (previous == null) System.clearProperty("jdk.httpclient.HttpClient.log");
            else System.setProperty("jdk.httpclient.HttpClient.log", previous);
        }
    }

    @Test
    void disabledAndMalformedInputsMakeNoRequest() {
        assertThat(validator(false, Duration.ofSeconds(1)).validate(CLASSIC).result())
                .isEqualTo("UNCHECKED");
        assertThat(validator(true, Duration.ofSeconds(1)).validate("ghs_not-a-pat").result())
                .isEqualTo("UNCHECKED");
        assertThat(calls).hasValue(0);
        assertThatThrownBy(
                        () ->
                                new GitHubPatValidator(
                                        true,
                                        URI.create("https://attacker.example/user"),
                                        Duration.ofSeconds(1)))
                .hasMessage("UNREGISTERED_VALIDATION_ENDPOINT");
    }
}
