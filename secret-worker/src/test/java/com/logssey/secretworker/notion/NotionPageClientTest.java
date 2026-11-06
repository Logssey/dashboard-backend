package com.logssey.secretworker.notion;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class NotionPageClientTest {
  private static final String PAGE = "11111111-2222-3333-4444-555555555555";
  private static final NotionApprovedScope SCOPE = new NotionApprovedScope(PAGE);
  private HttpServer server;
  private ExecutorService executor;
  private URI base;
  private NotionPageClient client;
  private final AtomicInteger requests = new AtomicInteger();

  @BeforeEach
  void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    executor = Executors.newVirtualThreadPerTaskExecutor();
    server.setExecutor(executor);
    server.start();
    base = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/");
    client = new NotionPageClient(base, () -> "fixture_collector_token", Duration.ofSeconds(2));
  }

  @AfterEach
  void stop() {
    server.stop(0);
    executor.shutdownNow();
  }

  @ParameterizedTest
  @ValueSource(ints = {401, 403, 404, 429, 500, 503, 529})
  void classifiesProviderErrorsWithoutEchoingTheirMessages(int status) {
    route(
        exchange -> {
          exchange.getResponseHeaders().set("Retry-After", "3600");
          NotionCollectorTest.reply(exchange, status, "{\"message\":\"private-response-marker\"}");
        });
    Instant started = Instant.now();
    assertThatThrownBy(() -> client.metadata(SCOPE, Duration.ofSeconds(2)))
        .isInstanceOfSatisfying(
            NotionSourceException.class,
            error -> {
              assertThat(error.status()).isEqualTo(status);
              assertThat(error.getMessage())
                  .doesNotContain("private-response-marker", "fixture_collector_token");
              if (status == 429 || status >= 500)
                assertThat(error.retryAt()).isAfter(started.plusSeconds(3590));
              if (status == 429)
                assertThat(error.code()).isEqualTo(NotionSourceException.Code.RATE_LIMITED);
              if (status == 401 || status == 403)
                assertThat(error.code()).isEqualTo(NotionSourceException.Code.ACCESS_DENIED);
              if (status == 404)
                assertThat(error.code()).isEqualTo(NotionSourceException.Code.NOT_FOUND);
            });
    assertThat(requests).hasValue(1);
  }

  @Test
  void identifiesPermanentApiRestrictionsFromAComplete429Body() {
    route(
        exchange -> {
          exchange.getResponseHeaders().set("Retry-After", "900");
          NotionCollectorTest.reply(
              exchange,
              429,
              "{\"code\":\"rate_limited\",\"additional_data\":{\"rate_limit_reason\":\"public_api_request_blocked\"}}");
        });
    assertThatThrownBy(() -> client.metadata(SCOPE, Duration.ofSeconds(2)))
        .isInstanceOfSatisfying(
            NotionSourceException.class,
            error -> {
              assertThat(error.code())
                  .isEqualTo(NotionSourceException.Code.PROVIDER_ACCESS_BLOCKED);
              assertThat(error.retryAt()).isNull();
            });
  }

  @Test
  void keepsRetryAfterWhen429BodyStallsPastTheWholeRequestDeadline() {
    route(
        exchange -> {
          exchange.getResponseHeaders().set("Retry-After", "3600");
          exchange.sendResponseHeaders(429, 100);
          exchange.getResponseBody().flush();
          try {
            Thread.sleep(2000);
          } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
          }
          exchange.close();
        });
    Instant started = Instant.now();
    assertThatThrownBy(() -> client.metadata(SCOPE, Duration.ofMillis(400)))
        .isInstanceOfSatisfying(
            NotionSourceException.class,
            error -> {
              assertThat(error.code()).isEqualTo(NotionSourceException.Code.RATE_LIMITED);
              assertThat(error.retryAt()).isAfter(started.plusSeconds(3590));
            });
    assertThat(Duration.between(started, Instant.now())).isLessThan(Duration.ofSeconds(3));
    assertThat(requests).hasValue(1);
  }

  @Test
  void keepsRetryAfterWhenThe429BodyEndsPrematurely() {
    route(
        exchange -> {
          exchange.getResponseHeaders().set("Retry-After", "3600");
          exchange.sendResponseHeaders(429, 100);
          exchange.getResponseBody().write('{');
          exchange.close();
        });
    Instant started = Instant.now();
    assertThatThrownBy(() -> client.metadata(SCOPE, Duration.ofSeconds(2)))
        .isInstanceOfSatisfying(
            NotionSourceException.class,
            error -> {
              assertThat(error.code()).isEqualTo(NotionSourceException.Code.RATE_LIMITED);
              assertThat(error.retryAt()).isAfter(started.plusSeconds(3590));
            });
    assertThat(requests).hasValue(1);
  }

  @Test
  void successBodyReadingIsInsideTheWholeRequestDeadline() {
    route(
        exchange -> {
          exchange.sendResponseHeaders(200, 100);
          exchange.getResponseBody().flush();
          try {
            Thread.sleep(2000);
          } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
          }
          exchange.close();
        });
    Instant started = Instant.now();
    assertThatThrownBy(() -> client.metadata(SCOPE, Duration.ofMillis(400)))
        .isInstanceOfSatisfying(
            NotionSourceException.class,
            error -> assertThat(error.code()).isEqualTo(NotionSourceException.Code.TIMEOUT));
    assertThat(Duration.between(started, Instant.now())).isLessThan(Duration.ofSeconds(3));
  }

  @Test
  void doesNotFollowRedirectsOrRetryTransportErrors() {
    route(
        exchange -> {
          exchange.getResponseHeaders().set("Location", base.resolve("capture").toString());
          NotionCollectorTest.reply(exchange, 302, "{}");
        });
    assertThatThrownBy(() -> client.metadata(SCOPE, Duration.ofSeconds(2)))
        .isInstanceOf(NotionSourceException.class);
    assertThat(requests).hasValue(1);
  }

  @Test
  void rejectsOversizedAndMalformedSuccessfulResponses() {
    route(
        exchange ->
            NotionCollectorTest.reply(
                exchange, 200, " ".repeat(NotionPageClient.MAX_METADATA_BYTES + 1)));
    assertThatThrownBy(() -> client.metadata(SCOPE, Duration.ofSeconds(2)))
        .isInstanceOfSatisfying(
            NotionSourceException.class,
            error ->
                assertThat(error.code()).isEqualTo(NotionSourceException.Code.RESPONSE_TOO_LARGE));
  }

  @Test
  void rejectsMismatchedPageIdentityAndMalformedBodyWithoutLeakingContent() {
    route(
        exchange ->
            NotionCollectorTest.reply(
                exchange,
                200,
                NotionCollectorTest.metadata("private-title", "2026-01-01T00:00:00.000Z")
                    .replace(PAGE, "aaaaaaaa-2222-3333-4444-555555555555")));
    assertThatThrownBy(() -> client.metadata(SCOPE, Duration.ofSeconds(2)))
        .isInstanceOf(NotionSourceException.class)
        .hasMessage("MALFORMED_RESPONSE")
        .hasMessageNotContaining("private-title");
  }

  @Test
  void unsafeLoggingAndMissingCredentialsPreventAnyRequest() {
    var unavailable =
        new NotionPageClient(
            base,
            () -> {
              throw new IllegalStateException("private-token-path");
            },
            Duration.ofSeconds(2));
    assertThatThrownBy(() -> unavailable.metadata(SCOPE, Duration.ofSeconds(2)))
        .isInstanceOf(NotionSourceException.class)
        .hasMessage("CONFIGURATION_ERROR");
    String original = System.getProperty("jdk.httpclient.HttpClient.log");
    try {
      System.setProperty("jdk.httpclient.HttpClient.log", "headers");
      assertThatThrownBy(() -> client.metadata(SCOPE, Duration.ofSeconds(2)))
          .isInstanceOf(NotionSourceException.class)
          .hasMessage("CONFIGURATION_ERROR");
    } finally {
      if (original == null) System.clearProperty("jdk.httpclient.HttpClient.log");
      else System.setProperty("jdk.httpclient.HttpClient.log", original);
    }
    assertThat(requests).hasValue(0);
  }

  @Test
  void restrictsEndpointAndExhaustedBudgetBeforeSending() {
    for (String address :
        List.of("https://example.test/", "http://127.0.0.1/path/", "http://user@127.0.0.1/")) {
      assertThatThrownBy(
              () ->
                  new NotionPageClient(URI.create(address), () -> "fixture", Duration.ofSeconds(2)))
          .isInstanceOf(IllegalArgumentException.class)
          .hasMessage("UNREGISTERED_NOTION_ENDPOINT");
    }
    assertThatThrownBy(() -> client.metadata(SCOPE, Duration.ZERO))
        .isInstanceOf(NotionSourceException.class)
        .hasMessage("TIMEOUT");
    assertThat(requests).hasValue(0);
  }

  @Test
  void encodesOpaqueCursorsAndUsesOnlyTheRegisteredChildrenPath() {
    route(
        exchange -> {
          assertThat(exchange.getRequestURI().getPath())
              .isEqualTo("/v1/blocks/" + PAGE + "/children");
          assertThat(exchange.getRequestURI().getRawQuery())
              .contains("start_cursor=opaque+cursor%3Fx%23fragment");
          NotionCollectorTest.reply(
              exchange, 200, NotionCollectorTest.page(List.of(), false, null));
        });
    assertThat(client.children(PAGE, "opaque cursor?x#fragment", Duration.ofSeconds(2)).blocks())
        .isEmpty();
    assertThat(requests).hasValue(1);
  }

  private void route(com.sun.net.httpserver.HttpHandler handler) {
    server.createContext(
        "/",
        exchange -> {
          requests.incrementAndGet();
          handler.handle(exchange);
        });
  }
}
