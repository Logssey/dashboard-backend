package com.logssey.secretworker.notion;

import java.io.IOException;
import com.logssey.secret.run.progress.core.ScanExecutionObserver;
import static com.logssey.secret.run.progress.core.ScanExecutionObserver.*;
import java.net.URI;
import java.net.URLEncoder;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.io.CloseMode;
import org.apache.hc.core5.util.Timeout;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Read-only, bounded requests to the registered Notion page and block endpoints. */
public final class NotionPageClient {
  public static final String API_VERSION = "2026-03-11";
  public static final int MAX_METADATA_BYTES = 262_144;
  public static final int MAX_BLOCK_RESPONSE_BYTES = 2_097_152;
  private static final URI API = URI.create("https://api.notion.com/");
  private ScanExecutionObserver observer = ScanExecutionObserver.NONE;
  private final URI base;
  private final Supplier<String> tokens;
  private final Duration requestTimeout;
  private final JsonMapper json = new JsonMapper();

  public NotionPageClient(Supplier<String> tokens) {
    this(API, tokens, Duration.ofSeconds(8));
  }

  // Loopback is a test seam, never a connection or page-supplied URL.
  NotionPageClient(URI base, Supplier<String> tokens, Duration requestTimeout) {
    boolean local =
        "http".equals(base.getScheme())
            && "127.0.0.1".equals(base.getHost())
            && "/".equals(base.getPath())
            && base.getUserInfo() == null
            && base.getQuery() == null
            && base.getFragment() == null;
    if ((!API.equals(base) && !local)
        || requestTimeout == null
        || requestTimeout.isZero()
        || requestTimeout.isNegative()
        || requestTimeout.compareTo(Duration.ofSeconds(8)) > 0) {
      throw new IllegalArgumentException("UNREGISTERED_NOTION_ENDPOINT");
    }
    this.base = base;
    this.tokens = Objects.requireNonNull(tokens);
    this.requestTimeout = requestTimeout;
  }

  NotionPageClient observed(ScanExecutionObserver observer) {
    var copy = new NotionPageClient(base, tokens, requestTimeout);
    copy.observer = Objects.requireNonNull(observer);
    return copy;
  }

  public record PageMetadata(
      String pageId,
      String lastEditedTime,
      boolean inTrash,
      boolean publishedToWeb,
      byte[] titleUtf8)
      implements AutoCloseable {
    @Override
    public void close() {
      Arrays.fill(titleUtf8, (byte) 0);
    }

    @Override
    public String toString() {
      return "NotionPageMetadata[inTrash=" + inTrash + ", published=" + publishedToWeb + "]";
    }
  }

  /** Contents are owned by the current collector callback and never persisted directly. */
  public record BlockPage(List<JsonNode> blocks, boolean hasMore, String nextCursor) {
    public BlockPage {
      blocks = List.copyOf(blocks);
    }

    @Override
    public String toString() {
      return "NotionBlockPage[count=" + blocks.size() + "]";
    }
  }

  public PageMetadata metadata(NotionApprovedScope scope, Duration budget) {
    JsonNode page = get("v1/pages/" + scope.pageId(), MAX_METADATA_BYTES, budget);
    if (!"page".equals(page.path("object").asText(""))
        || !scope.pageId().equals(id(page.path("id")))) throw malformed();
    String edited = page.path("last_edited_time").asText("");
    try {
      Instant.parse(edited);
    } catch (RuntimeException ignored) {
      throw malformed();
    }
    JsonNode archived = page.path("archived");
    if (edited.length() > 64
        || (!archived.isMissingNode() && !archived.isBoolean())
        || !page.path("in_trash").isBoolean()) throw malformed();
    JsonNode properties = page.path("properties");
    if (!properties.isObject()) throw malformed();
    JsonNode title = null;
    for (JsonNode property : properties) {
      if ("title".equals(property.path("type").asText(""))) {
        if (title != null || !property.path("title").isArray()) throw malformed();
        title = property.path("title");
      }
    }
    if (title == null) throw malformed();
    String text = richText(title);
    if (text == null) throw malformed();
    boolean published =
        page.path("public_url").isTextual() && !page.path("public_url").asText("").isBlank();
    return new PageMetadata(
        scope.pageId(),
        edited,
        archived.asBoolean(false) || page.path("in_trash").asBoolean(),
        published,
        text.getBytes(StandardCharsets.UTF_8));
  }

  public BlockPage children(String blockId, String cursor, Duration budget) {
    String path =
        "v1/blocks/" + NotionApprovedScope.canonicalId(blockId) + "/children?page_size=100";
    if (cursor != null) {
      if (cursor.isBlank() || cursor.length() > 1_024) throw malformed();
      path += "&start_cursor=" + URLEncoder.encode(cursor, StandardCharsets.UTF_8);
    }
    JsonNode page = get(path, MAX_BLOCK_RESPONSE_BYTES, budget);
    if (!"list".equals(page.path("object").asText(""))
        || !page.path("results").isArray()
        || !page.path("has_more").isBoolean()
        || page.path("results").size() > 100) throw malformed();
    boolean more = page.path("has_more").asBoolean();
    JsonNode cursorNode = page.path("next_cursor");
    if (more
        && (!cursorNode.isTextual()
            || cursorNode.asText().isBlank()
            || cursorNode.asText().length() > 1_024)) throw malformed();
    var rows = new ArrayList<JsonNode>();
    for (JsonNode row : page.path("results")) rows.add(row);
    return new BlockPage(rows, more, more ? cursorNode.asText() : null);
  }

  static String id(JsonNode value) {
    if (!value.isTextual()) throw malformed();
    try {
      return NotionApprovedScope.canonicalId(value.asText());
    } catch (IllegalArgumentException ignored) {
      throw malformed();
    }
  }

  static String richText(JsonNode values) {
    if (!values.isArray()) return null;
    var text = new StringBuilder();
    for (JsonNode value : values) {
      JsonNode plain = value.path("plain_text");
      JsonNode content = value.path("text").path("content");
      if (plain.isTextual()) text.append(plain.asText());
      else if (content.isTextual()) text.append(content.asText());
      else return null;
    }
    return text.toString();
  }

  private JsonNode get(String path, int maxBytes, Duration budget) {
    if (budget == null || budget.isZero() || budget.isNegative())
      throw new NotionSourceException(NotionSourceException.Code.TIMEOUT, 0);
    if (!safeLogging())
      throw new NotionSourceException(NotionSourceException.Code.CONFIGURATION_ERROR, 0);
    Duration timeout = requestTimeout.compareTo(budget) < 0 ? requestTimeout : budget;
    long deadline = System.nanoTime() + timeout.toNanos();
    var request = new HttpGet(base.resolve(path));
    request.setHeader("Notion-Version", API_VERSION);
    request.setHeader("Accept", "application/json");
    request.setHeader("User-Agent", "logssey-secret-worker");
    var manager =
        PoolingHttpClientConnectionManagerBuilder.create()
            .setDefaultConnectionConfig(
                ConnectionConfig.custom().setConnectTimeout(Timeout.ofSeconds(3)).build())
            .build();
    var http =
        HttpClients.custom()
            .setConnectionManager(manager)
            .setDefaultRequestConfig(
                RequestConfig.custom()
                    .setConnectionRequestTimeout(Timeout.ofSeconds(3))
                    .setResponseTimeout(Timeout.ofMilliseconds(Math.max(1, timeout.toMillis())))
                    .build())
            .disableAutomaticRetries()
            .disableRedirectHandling()
            .disableCookieManagement()
            .disableAuthCaching()
            .disableContentCompression()
            .build();
    var executor = Executors.newVirtualThreadPerTaskExecutor();
    var headers = new AtomicReference<NotionSourceException>();
    Future<JsonNode> pending = null;
    try {
      pending =
          executor.submit(
              () -> {
                String token;
                try {
                  token = tokens.get();
                } catch (RuntimeException ignored) {
                  throw new NotionSourceException(
                      NotionSourceException.Code.CONFIGURATION_ERROR, 0);
                }
                if (token == null
                    || token.isBlank()
                    || token.length() > 4_096
                    || !token.matches("[A-Za-z0-9_]+"))
                  throw new NotionSourceException(
                      NotionSourceException.Code.CONFIGURATION_ERROR, 0);
                if (Thread.currentThread().isInterrupted() || System.nanoTime() >= deadline)
                  throw new NotionSourceException(NotionSourceException.Code.TIMEOUT, 0);
                request.setHeader("Authorization", "Bearer " + token);
                Operation operation = path.startsWith("v1/pages/")
                    ? Operation.NOTION_PAGE_GET : Operation.NOTION_BLOCK_CHILDREN_LIST;
                observer.record(Stage.COLLECTION, operation, Outcome.STARTED, null, null, null, null, null);
                long operationStarted = System.nanoTime();
                org.apache.hc.core5.http.ClassicHttpResponse response;
                try {
                  response = http.executeOpen(null, request, null);
                } catch (IOException failure) {
                  observer.record(Stage.COLLECTION, operation, Outcome.FAILED, null,
                      "NETWORK_ERROR", null, null, ScanExecutionObserver.elapsed(operationStarted));
                  throw failure;
                }
                try {
                  int status = response.getCode();
                  observer.record(Stage.COLLECTION, operation,
                      status >= 200 && status < 300 ? Outcome.COMPLETED : Outcome.FAILED,
                      status, status >= 200 && status < 300 ? null : status == 429 ? "RATE_LIMITED"
                          : status == 401 || status == 403 ? "ACCESS_DENIED" : "OPERATION_FAILED",
                      null, null, ScanExecutionObserver.elapsed(operationStarted));
                  var error = error(response);
                  if (error != null) {
                    headers.set(error);
                    if (status != 429) throw error;
                  }
                  byte[] bytes =
                      response.getEntity() == null
                          ? new byte[0]
                          : response.getEntity().getContent().readNBytes(maxBytes + 1);
                  try {
                    if (bytes.length > maxBytes) {
                      if (error != null) throw error;
                      throw new NotionSourceException(
                          NotionSourceException.Code.RESPONSE_TOO_LARGE, status);
                    }
                    JsonNode body;
                    try {
                      body = json.readTree(bytes);
                    } catch (RuntimeException ignored) {
                      throw error != null ? error : malformed();
                    }
                    if (status == 429) {
                      if (body != null
                          && "public_api_request_blocked"
                              .equals(
                                  body.path("additional_data")
                                      .path("rate_limit_reason")
                                      .asText(""))) {
                        throw new NotionSourceException(
                            NotionSourceException.Code.PROVIDER_ACCESS_BLOCKED, status);
                      }
                      throw error;
                    }
                    if (body == null || !body.isObject()) throw malformed();
                    return body;
                  } finally {
                    Arrays.fill(bytes, (byte) 0);
                  }
                } finally {
                  request.cancel();
                  try {
                    response.close();
                  } catch (IOException ignored) {
                  }
                }
              });
      return pending.get(Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
    } catch (InterruptedException ignored) {
      Thread.currentThread().interrupt();
      throw headers.get() != null
          ? headers.get()
          : new NotionSourceException(NotionSourceException.Code.SOURCE_UNAVAILABLE, 0);
    } catch (TimeoutException ignored) {
      throw headers.get() != null
          ? headers.get()
          : new NotionSourceException(NotionSourceException.Code.TIMEOUT, 0);
    } catch (ExecutionException error) {
      if (error.getCause() instanceof NotionSourceException safe) throw safe;
      throw headers.get() != null
          ? headers.get()
          : new NotionSourceException(error.getCause() instanceof SocketTimeoutException
              ? NotionSourceException.Code.TIMEOUT : NotionSourceException.Code.SOURCE_UNAVAILABLE, 0);
    } catch (RuntimeException error) {
      if (error instanceof NotionSourceException safe) throw safe;
      throw new NotionSourceException(NotionSourceException.Code.SOURCE_UNAVAILABLE, 0);
    } finally {
      request.cancel();
      if (pending != null && !pending.isDone()) pending.cancel(true);
      http.close(CloseMode.IMMEDIATE);
      executor.shutdownNow();
    }
  }

  private static NotionSourceException error(HttpResponse response) {
    int status = response.getCode();
    if (status == 200) return null;
    if (status == 429 || status >= 500) {
      return new NotionSourceException(
          status == 429
              ? NotionSourceException.Code.RATE_LIMITED
              : NotionSourceException.Code.SOURCE_UNAVAILABLE,
          status,
          retryAt(response));
    }
    return new NotionSourceException(
        switch (status) {
          case 401, 403 -> NotionSourceException.Code.ACCESS_DENIED;
          case 404 -> NotionSourceException.Code.NOT_FOUND;
          default -> NotionSourceException.Code.MALFORMED_RESPONSE;
        },
        status);
  }

  private static Instant retryAt(HttpResponse response) {
    var header = response.getFirstHeader("Retry-After");
    if (header == null) return response.getCode() == 429 ? Instant.now().plusSeconds(60) : null;
    Instant now = Instant.now();
    try {
      return now.plusSeconds(Math.max(1, Long.parseLong(header.getValue())));
    } catch (RuntimeException ignored) {
      try {
        Instant at =
            ZonedDateTime.parse(header.getValue(), DateTimeFormatter.RFC_1123_DATE_TIME)
                .toInstant();
        return at.isAfter(now) ? at : now.plusSeconds(1);
      } catch (RuntimeException ignoredDate) {
        return now.plusSeconds(60);
      }
    }
  }

  private static boolean safeLogging() {
    return System.getProperty("jdk.httpclient.HttpClient.log", "").isBlank()
        && !LoggerFactory.getLogger("org.apache.hc.client5.http").isDebugEnabled()
        && !LoggerFactory.getLogger("org.apache.hc.client5.http.headers").isDebugEnabled()
        && !LoggerFactory.getLogger("org.apache.hc.client5.http.wire").isDebugEnabled();
  }

  private static NotionSourceException malformed() {
    return new NotionSourceException(NotionSourceException.Code.MALFORMED_RESPONSE, 200);
  }
}
