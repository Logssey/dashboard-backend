package com.logssey.secretworker.notion;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

class NotionCollectorTest {
  private static final String PAGE = "11111111-2222-3333-4444-555555555555";
  private static final String BLOCK_A = "aaaaaaaa-2222-3333-4444-555555555555";
  private static final String BLOCK_B = "bbbbbbbb-2222-3333-4444-555555555555";
  private static final String EDITED = "2026-01-01T00:00:00.000Z";
  private static final JsonMapper JSON = new JsonMapper();
  private HttpServer server;
  private ExecutorService executor;
  private NotionPageClient client;
  private final AtomicInteger requests = new AtomicInteger();

  @BeforeEach
  void start() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    executor = Executors.newVirtualThreadPerTaskExecutor();
    server.setExecutor(executor);
    server.start();
    client =
        new NotionPageClient(
            URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/"),
            () -> "fixture_collector_token",
            Duration.ofSeconds(2));
  }

  @AfterEach
  void stop() {
    server.stop(0);
    executor.shutdownNow();
  }

  @Test
  void readsTitleNestedCodeAndPaginationWithStableBlockReferences() {
    route(
        exchange -> {
          if (metadataPath(exchange))
            reply(exchange, 200, metadata("private title marker", EDITED));
          else if (exchange.getRequestURI().getPath().contains(BLOCK_A))
            reply(
                exchange,
                200,
                page(
                    List.of(
                        block(
                            BLOCK_B,
                            "code",
                            "AWS_ACCESS_KEY_ID=sample\nAWS_SECRET_ACCESS_KEY=sample",
                            BLOCK_A,
                            "block_id",
                            false)),
                    false,
                    null));
          else if (exchange.getRequestURI().getRawQuery().contains("start_cursor="))
            reply(exchange, 200, page(List.of(), false, null));
          else
            reply(
                exchange,
                200,
                page(
                    List.of(block(BLOCK_A, "toggle", "한국어 안내 🔐", PAGE, "page_id", true)),
                    true,
                    "next cursor"));
        });
    var sources = new ArrayList<NotionCollector.Source>();
    var borrowed = new ArrayList<byte[]>();
    var values = new ArrayList<String>();
    var guard = new AtomicInteger();
    var result =
        new NotionCollector(client)
            .collect(
                new NotionApprovedScope(PAGE),
                NotionCollectionLimits.DEFAULT,
                (source, bytes) -> {
                  sources.add(source);
                  borrowed.add(bytes);
                  values.add(new String(bytes, StandardCharsets.UTF_8));
                },
                guard::incrementAndGet);

    assertThat(result.status()).isEqualTo(NotionCollector.Status.SUCCEEDED);
    assertThat(result.comparable()).isTrue();
    assertThat(result.objectCount()).isEqualTo(3);
    assertThat(sources)
        .extracting(NotionCollector.Source::sourceObjectRef)
        .containsExactly(
            "notion/pages/" + PAGE + "/title",
            "notion/pages/" + PAGE + "/blocks/" + BLOCK_A,
            "notion/pages/" + PAGE + "/blocks/" + BLOCK_B);
    assertThat(values)
        .contains(
            "private title marker",
            "한국어 안내 🔐",
            "AWS_ACCESS_KEY_ID=sample\nAWS_SECRET_ACCESS_KEY=sample");
    assertThat(guard).hasValue(requests.get());
    assertThat(borrowed).allSatisfy(bytes -> assertThat(bytes).containsOnly((byte) 0));
    assertThat(result.toString() + sources)
        .doesNotContain("private title marker", "fixture_collector_token");
  }

  @Test
  void emitsOneTitleObjectForAnEmptyApprovedPage() {
    route(
        exchange ->
            reply(
                exchange,
                200,
                metadataPath(exchange) ? metadata("", EDITED) : page(List.of(), false, null)));
    var sizes = new ArrayList<Integer>();
    var result =
        new NotionCollector(client)
            .collect(
                new NotionApprovedScope(PAGE),
                NotionCollectionLimits.DEFAULT,
                (source, bytes) -> {
                  assertThat(source.title()).isTrue();
                  sizes.add(bytes.length);
                });
    assertThat(result.status()).isEqualTo(NotionCollector.Status.SUCCEEDED);
    assertThat(result.objectCount()).isEqualTo(1);
    assertThat(sizes).containsExactly(0);
  }

  @Test
  void preservesReadObjectsAndCooldownWhenTheNextCursorFails() {
    route(
        exchange -> {
          if (metadataPath(exchange)) reply(exchange, 200, metadata("", EDITED));
          else if (exchange.getRequestURI().getRawQuery().contains("start_cursor=")) {
            exchange.getResponseHeaders().set("Retry-After", "3600");
            reply(exchange, 429, "{\"code\":\"rate_limited\"}");
          } else
            reply(
                exchange,
                200,
                page(
                    List.of(block(BLOCK_A, "paragraph", "found text", PAGE, "page_id", false)),
                    true,
                    "second"));
        });
    var sources = new ArrayList<NotionCollector.Source>();
    Instant at = Instant.now();
    var result =
        new NotionCollector(client)
            .collect(
                new NotionApprovedScope(PAGE),
                NotionCollectionLimits.DEFAULT,
                (source, bytes) -> sources.add(source));
    assertThat(result.status()).isEqualTo(NotionCollector.Status.PARTIAL);
    assertThat(result.objectCount()).isEqualTo(2);
    assertThat(result.comparable()).isFalse();
    assertThat(result.nextRetryAt()).isAfter(at.plusSeconds(3590));
    assertThat(result.failureCode()).isEqualTo("NOTION_RATE_LIMITED");
    assertThat(sources)
        .allSatisfy(
            source -> {
              assertThat(source.comparable()).isFalse();
              assertThat(source.nextRetryAt()).isEqualTo(result.nextRetryAt());
            });
    assertThat(requests).hasValue(3);
  }

  @Test
  void changesDuringPaginationPreventAbsenceComparability() {
    var metadataCalls = new AtomicInteger();
    route(
        exchange ->
            reply(
                exchange,
                200,
                metadataPath(exchange)
                    ? metadata(
                        "",
                        metadataCalls.incrementAndGet() == 1 ? EDITED : "2026-01-01T00:01:00.000Z")
                    : page(
                        List.of(block(BLOCK_A, "paragraph", "observed", PAGE, "page_id", false)),
                        false,
                        null)));
    var result =
        new NotionCollector(client)
            .collect(
                new NotionApprovedScope(PAGE),
                NotionCollectionLimits.DEFAULT,
                (source, bytes) -> assertThat(source.comparable()).isFalse());
    assertThat(result.status()).isEqualTo(NotionCollector.Status.PARTIAL);
    assertThat(result.gaps())
        .extracting(NotionCollector.Gap::code)
        .contains(NotionSourceException.Code.CONTENT_CHANGED);
  }

  @Test
  void doesNotReadAnUnapprovedParentOrFollowExternalReferences() {
    var foreign = block(BLOCK_A, "paragraph", "should not be emitted", BLOCK_B, "page_id", true);
    route(
        exchange ->
            reply(
                exchange,
                200,
                metadataPath(exchange)
                    ? metadata("", EDITED)
                    : page(List.of(foreign), false, null)));
    var sources = new ArrayList<NotionCollector.Source>();
    var result =
        new NotionCollector(client)
            .collect(
                new NotionApprovedScope(PAGE),
                NotionCollectionLimits.DEFAULT,
                (source, bytes) -> sources.add(source));
    assertThat(sources).hasSize(1);
    assertThat(result.comparable()).isFalse();
    assertThat(result.gaps())
        .extracting(NotionCollector.Gap::code)
        .contains(NotionSourceException.Code.MALFORMED_RESPONSE);
    assertThat(requests).hasValue(3);
  }

  @Test
  void boundsTheNumberOfTraversedBlocks() {
    route(
        exchange ->
            reply(
                exchange,
                200,
                metadataPath(exchange)
                    ? metadata("", EDITED)
                    : page(
                        List.of(
                            block(BLOCK_A, "paragraph", "first", PAGE, "page_id", false),
                            block(BLOCK_B, "paragraph", "second", PAGE, "page_id", false)),
                        false,
                        null)));
    var result =
        new NotionCollector(client)
            .collect(
                new NotionApprovedScope(PAGE),
                new NotionCollectionLimits(1, 2, 10, 1024, Duration.ofSeconds(5)),
                (source, bytes) -> {});
    assertThat(result.gaps())
        .extracting(NotionCollector.Gap::code)
        .contains(NotionSourceException.Code.BLOCK_LIMIT);
    assertThat(result.comparable()).isFalse();
    assertThat(requests).hasValue(2);
  }

  @Test
  void recordsATextLimitWithoutTruncatingOrPromotingTheScope() {
    route(
        exchange ->
            reply(
                exchange,
                200,
                metadataPath(exchange)
                    ? metadata("", EDITED)
                    : page(
                        List.of(
                            block(BLOCK_A, "paragraph", "too much text", PAGE, "page_id", false)),
                        false,
                        null)));
    var result =
        new NotionCollector(client)
            .collect(
                new NotionApprovedScope(PAGE),
                new NotionCollectionLimits(20, 4, 10, 4, Duration.ofSeconds(5)),
                (source, bytes) -> {});
    assertThat(result.gaps())
        .extracting(NotionCollector.Gap::code)
        .contains(NotionSourceException.Code.TEXT_LIMIT);
    assertThat(result.objectCount()).isEqualTo(1);
    assertThat(result.byteCount()).isZero();
    assertThat(result.comparable()).isFalse();
    assertThat(requests).hasValue(2);
  }

  @Test
  void depthLimitPreservesObservedTextAndStopsDeeperRequests() {
    route(
        exchange -> {
          if (metadataPath(exchange)) reply(exchange, 200, metadata("", EDITED));
          else if (exchange.getRequestURI().getPath().contains(BLOCK_A))
            reply(
                exchange,
                200,
                page(
                    List.of(block(BLOCK_B, "toggle", "inner", BLOCK_A, "block_id", true)),
                    false,
                    null));
          else
            reply(
                exchange,
                200,
                page(
                    List.of(block(BLOCK_A, "toggle", "outer", PAGE, "page_id", true)),
                    false,
                    null));
        });
    var result =
        new NotionCollector(client)
            .collect(
                new NotionApprovedScope(PAGE),
                new NotionCollectionLimits(20, 1, 10, 1024, Duration.ofSeconds(5)),
                (source, bytes) -> {});
    assertThat(result.objectCount()).isEqualTo(3);
    assertThat(result.gaps())
        .extracting(NotionCollector.Gap::code)
        .contains(NotionSourceException.Code.DEPTH_LIMIT);
    assertThat(result.comparable()).isFalse();
    assertThat(requests).hasValue(4);
  }

  @Test
  void repeatedCursorIsAnExplicitGap() {
    route(
        exchange ->
            reply(
                exchange,
                200,
                metadataPath(exchange)
                    ? metadata("", EDITED)
                    : page(List.of(), true, "same-cursor")));
    var result =
        new NotionCollector(client)
            .collect(
                new NotionApprovedScope(PAGE),
                NotionCollectionLimits.DEFAULT,
                (source, bytes) -> {});
    assertThat(result.gaps())
        .extracting(NotionCollector.Gap::code)
        .contains(NotionSourceException.Code.CURSOR_LOOP);
    assertThat(requests).hasValue(4);
  }

  @Test
  void childPagesLinksAndExternalSyncedBlocksAreNeverFollowed() {
    var child = new HashMap<>(block(BLOCK_A, "child_page", "", PAGE, "page_id", true));
    child.put("child_page", Map.of("title", "visible child title"));
    var link = new HashMap<>(block(BLOCK_B, "link_to_page", "", PAGE, "page_id", true));
    link.put(
        "link_to_page",
        Map.of("type", "page_id", "page_id", "cccccccc-2222-3333-4444-555555555555"));
    var synced =
        new HashMap<>(
            block(
                "dddddddd-2222-3333-4444-555555555555", "synced_block", "", PAGE, "page_id", true));
    synced.put("synced_block", Map.of("synced_from", Map.of("block_id", BLOCK_B)));
    route(
        exchange ->
            reply(
                exchange,
                200,
                metadataPath(exchange)
                    ? metadata("", EDITED)
                    : page(List.of(child, link, synced), false, null)));
    var sources = new ArrayList<NotionCollector.Source>();
    var result =
        new NotionCollector(client)
            .collect(
                new NotionApprovedScope(PAGE),
                NotionCollectionLimits.DEFAULT,
                (source, bytes) -> sources.add(source));
    assertThat(sources).hasSize(2);
    assertThat(result.excludedBlockCount()).isEqualTo(2);
    assertThat(result.gaps())
        .extracting(NotionCollector.Gap::code)
        .contains(NotionSourceException.Code.UNSUPPORTED_BLOCK);
    assertThat(requests).hasValue(3);
  }

  @Test
  void guardAndConsumerFailuresPropagateWithBuffersCleared() {
    route(
        exchange ->
            reply(
                exchange,
                200,
                metadataPath(exchange)
                    ? metadata("private marker", EDITED)
                    : page(
                        List.of(block(BLOCK_A, "paragraph", "text", PAGE, "page_id", false)),
                        false,
                        null)));
    var held = new ArrayList<byte[]>();
    assertThatThrownBy(
            () ->
                new NotionCollector(client)
                    .collect(
                        new NotionApprovedScope(PAGE),
                        NotionCollectionLimits.DEFAULT,
                        (source, bytes) -> {
                          held.add(bytes);
                          throw new IllegalStateException("lease lost");
                        }))
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("lease lost");
    assertThat(held).allSatisfy(bytes -> assertThat(bytes).containsOnly((byte) 0));
    var guards = new AtomicInteger();
    assertThatThrownBy(
            () ->
                new NotionCollector(client)
                    .collect(
                        new NotionApprovedScope(PAGE),
                        NotionCollectionLimits.DEFAULT,
                        (source, bytes) -> {},
                        () -> {
                          if (guards.incrementAndGet() == 2)
                            throw new IllegalStateException("approval changed");
                        }))
        .isInstanceOf(IllegalStateException.class)
        .hasMessage("approval changed");
  }

  @Test
  void approvedScopeRejectsUrlsQueriesHistoryAndNormalizesUuid() {
    assertThat(
            NotionApprovedScope.fromApprovedRef(
                    "notion://pages/" + PAGE.replace("-", ""), "CURRENT_VERSION_ONLY")
                .pageId())
        .isEqualTo(PAGE);
    for (String ref :
        List.of(
            "https://www.notion.so/" + PAGE,
            "notion://pages/" + PAGE + "?all=true",
            "notion://pages/" + PAGE + "/",
            "notion://pages/../" + PAGE)) {
      assertThatThrownBy(() -> NotionApprovedScope.fromApprovedRef(ref, "CURRENT_VERSION_ONLY"))
          .isInstanceOf(IllegalArgumentException.class);
    }
    assertThatThrownBy(
            () -> NotionApprovedScope.fromApprovedRef("notion://pages/" + PAGE, "ALL_HISTORY"))
        .isInstanceOf(IllegalArgumentException.class);
  }

  private void route(com.sun.net.httpserver.HttpHandler handler) {
    server.createContext(
        "/",
        exchange -> {
          requests.incrementAndGet();
          assertThat(exchange.getRequestMethod()).isEqualTo("GET");
          assertThat(exchange.getRequestHeaders().getFirst("Authorization"))
              .isEqualTo("Bearer fixture_collector_token");
          assertThat(exchange.getRequestHeaders().getFirst("Notion-Version"))
              .isEqualTo(NotionPageClient.API_VERSION);
          handler.handle(exchange);
        });
  }

  private static boolean metadataPath(HttpExchange exchange) {
    return exchange.getRequestURI().getPath().equals("/v1/pages/" + PAGE);
  }

  static String metadata(String title, String edited) {
    var map = new HashMap<String, Object>();
    map.put("object", "page");
    map.put("id", PAGE);
    map.put("last_edited_time", edited);
    map.put("archived", false);
    map.put("in_trash", false);
    map.put("public_url", null);
    map.put("properties", Map.of("title", Map.of("type", "title", "title", rich(title))));
    return JSON.writeValueAsString(map);
  }

  static Map<String, Object> block(
      String id, String type, String text, String parent, String parentType, boolean children) {
    return Map.of(
        "object",
        "block",
        "id",
        id,
        "type",
        type,
        "has_children",
        children,
        "parent",
        Map.of("type", parentType, parentType, parent),
        type,
        Map.of("rich_text", rich(text)));
  }

  static List<Map<String, Object>> rich(String text) {
    return List.of(Map.of("type", "text", "plain_text", text));
  }

  static String page(List<?> blocks, boolean more, String cursor) {
    var map = new HashMap<String, Object>();
    map.put("object", "list");
    map.put("results", blocks);
    map.put("has_more", more);
    map.put("next_cursor", cursor);
    return JSON.writeValueAsString(map);
  }

  static void reply(HttpExchange exchange, int status, String body) throws IOException {
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().set("Content-Type", "application/json");
    exchange.sendResponseHeaders(status, bytes.length);
    try (var output = exchange.getResponseBody()) {
      output.write(bytes);
    }
  }
}
