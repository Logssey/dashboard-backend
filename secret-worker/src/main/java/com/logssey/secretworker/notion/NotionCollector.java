package com.logssey.secretworker.notion;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import tools.jackson.databind.JsonNode;

/** Reads one approved page and emits bounded text objects with stable block identities. */
public final class NotionCollector {
  private static final Set<String> TEXT =
      Set.of(
          "paragraph",
          "heading_1",
          "heading_2",
          "heading_3",
          "bulleted_list_item",
          "numbered_list_item",
          "to_do",
          "toggle",
          "quote",
          "callout",
          "code",
          "template");
  private static final Set<String> CONTAINERS = Set.of("column_list", "column", "table");
  private static final Set<String> CAPTIONS =
      Set.of("image", "file", "pdf", "video", "audio", "bookmark", "embed");
  private static final Set<String> STRUCTURAL =
      Set.of("divider", "table_of_contents", "breadcrumb", "link_to_page");
  private final NotionPageClient client;

  public NotionCollector(NotionPageClient client) {
    this.client = Objects.requireNonNull(client);
  }

  @FunctionalInterface
  public interface ContentSink {
    void accept(Source source, byte[] utf8);
  }

  public enum Status {
    SUCCEEDED,
    PARTIAL,
    FAILED
  }

  public record Source(
      String pageId,
      String blockId,
      String version,
      boolean comparable,
      Instant nextRetryAt,
      String failureCode) {
    public boolean title() {
      return blockId == null;
    }

    public String sourceObjectRef() {
      return "notion/pages/" + pageId + (title() ? "/title" : "/blocks/" + blockId);
    }
  }

  public record Gap(String blockId, NotionSourceException.Code code) {}

  public record Result(
      Status status,
      int objectCount,
      long byteCount,
      List<Gap> gaps,
      boolean comparable,
      Instant nextRetryAt,
      int excludedBlockCount,
      boolean publishedToWeb) {
    public Result {
      gaps = List.copyOf(gaps);
    }

    public String failureCode() {
      return NotionCollector.failureCode(gaps, nextRetryAt);
    }

    @Override
    public String toString() {
      return "NotionCollectionResult[status="
          + status
          + ", objectCount="
          + objectCount
          + ", byteCount="
          + byteCount
          + ", gapCount="
          + gaps.size()
          + "]";
    }
  }

  public Result collect(
      NotionApprovedScope scope, NotionCollectionLimits limits, ContentSink sink) {
    return collect(scope, limits, sink, () -> {});
  }

  public Result collect(
      NotionApprovedScope scope,
      NotionCollectionLimits limits,
      ContentSink sink,
      Runnable beforeRequest) {
    Objects.requireNonNull(scope);
    Objects.requireNonNull(limits);
    Objects.requireNonNull(sink);
    State state = new State(scope, limits, Objects.requireNonNull(beforeRequest));
    NotionPageClient.PageMetadata before = null;
    try {
      try {
        beforeRequest.run();
        Duration firstBudget = state.remaining();
        state.requests++;
        before = client.metadata(scope, firstBudget);
        if (before.inTrash())
          throw new NotionSourceException(NotionSourceException.Code.IN_TRASH, 200);
        state.addDocument(null, before.titleUtf8().clone());
        state.walk(scope.pageId(), 0);
        if (!state.stopRequests) {
          beforeRequest.run();
          Duration finalBudget = state.remaining();
          state.requests++;
          try (var after = client.metadata(scope, finalBudget)) {
            if (after.inTrash()
                || !before.lastEditedTime().equals(after.lastEditedTime())
                || before.publishedToWeb() != after.publishedToWeb()) {
              state.gaps.add(new Gap(null, NotionSourceException.Code.CONTENT_CHANGED));
            }
          }
        }
      } catch (NotionSourceException error) {
        state.gap(null, error);
      }
      boolean comparable = state.gaps.isEmpty() && before != null;
      for (Document document : state.documents) {
        String version = "notion-v1:" + before.lastEditedTime() + ":" + sha(document.bytes);
        String failure = failureCode(state.gaps, state.retryAt);
        sink.accept(
            new Source(
                scope.pageId(), document.blockId, version, comparable, state.retryAt, failure),
            document.bytes);
        Arrays.fill(document.bytes, (byte) 0);
      }
      Status status =
          state.gaps.isEmpty()
              ? Status.SUCCEEDED
              : state.documents.isEmpty() ? Status.FAILED : Status.PARTIAL;
      return new Result(
          status,
          state.documents.size(),
          state.bytes,
          state.gaps,
          comparable,
          state.retryAt,
          state.excluded,
          before != null && before.publishedToWeb());
    } finally {
      for (Document document : state.documents) Arrays.fill(document.bytes, (byte) 0);
      if (before != null) before.close();
    }
  }

  private final class State {
    private final NotionApprovedScope scope;
    private final NotionCollectionLimits limits;
    private final Runnable beforeRequest;
    private final long started = System.nanoTime();
    private final List<Document> documents = new ArrayList<>();
    private final List<Gap> gaps = new ArrayList<>();
    private final Set<String> visited = new HashSet<>();
    private int requests;
    private int blocks;
    private int bytes;
    private int excluded;
    private Instant retryAt;
    private boolean stopRequests;

    private State(
        NotionApprovedScope scope, NotionCollectionLimits limits, Runnable beforeRequest) {
      this.scope = scope;
      this.limits = limits;
      this.beforeRequest = beforeRequest;
    }

    private Duration remaining() {
      if (requests >= limits.maxRequests())
        throw new NotionSourceException(NotionSourceException.Code.REQUEST_LIMIT, 0);
      Duration left = limits.totalTimeout().minusNanos(System.nanoTime() - started);
      if (left.isZero() || left.isNegative())
        throw new NotionSourceException(NotionSourceException.Code.TIMEOUT, 0);
      return left;
    }

    private void walk(String parentId, int depth) {
      if (depth > limits.maxDepth()) {
        gaps.add(new Gap(parentId, NotionSourceException.Code.DEPTH_LIMIT));
        return;
      }
      var cursors = new HashSet<String>();
      String cursor = null;
      do {
        NotionPageClient.BlockPage page;
        beforeRequest.run();
        try {
          Duration budget = remaining();
          requests++;
          page = client.children(parentId, cursor, budget);
        } catch (NotionSourceException error) {
          gap(parentId, error);
          return;
        }
        for (JsonNode block : page.blocks()) {
          if (++blocks > limits.maxBlocks()) {
            gaps.add(new Gap(parentId, NotionSourceException.Code.BLOCK_LIMIT));
            stopRequests = true;
            return;
          }
          try {
            block(block, parentId, depth);
          } catch (NotionSourceException error) {
            gap(parentId, error);
            if (Set.of(
                    NotionSourceException.Code.TEXT_LIMIT,
                    NotionSourceException.Code.TIMEOUT,
                    NotionSourceException.Code.REQUEST_LIMIT)
                .contains(error.code())) return;
          }
          if (stopRequests) return;
        }
        cursor = page.nextCursor();
        if (page.hasMore() && !cursors.add(cursor)) {
          gaps.add(new Gap(parentId, NotionSourceException.Code.CURSOR_LOOP));
          return;
        }
        if (!page.hasMore()) return;
      } while (true);
    }

    private void block(JsonNode block, String parentId, int depth) {
      if (!"block".equals(block.path("object").asText(""))
          || !block.path("has_children").isBoolean()) throw malformed();
      String id = NotionPageClient.id(block.path("id"));
      if (!visited.add(id)) throw malformed();
      JsonNode parent = block.path("parent");
      String expected = parentId.equals(scope.pageId()) ? "page_id" : "block_id";
      if (!expected.equals(parent.path("type").asText(""))
          || !parentId.equals(NotionPageClient.id(parent.path(expected)))) throw malformed();
      String type = block.path("type").asText("");
      JsonNode body = block.path(type);
      if (!body.isObject()) throw malformed();
      boolean traverse = true;
      String text;
      if (TEXT.contains(type)) text = NotionPageClient.richText(body.path("rich_text"));
      else if ("table_row".equals(type)) text = cells(body.path("cells"));
      else if ("equation".equals(type))
        text = body.path("expression").isTextual() ? body.path("expression").asText() : null;
      else if ("child_page".equals(type) || "child_database".equals(type)) {
        text = body.path("title").isTextual() ? body.path("title").asText() : null;
        traverse = false;
        excluded++;
      } else if (CAPTIONS.contains(type)) {
        text =
            body.path("caption").isMissingNode()
                ? ""
                : NotionPageClient.richText(body.path("caption"));
        traverse = false;
        excluded++;
      } else if (CONTAINERS.contains(type)) text = "";
      else if (STRUCTURAL.contains(type)) {
        text = "";
        traverse = false;
        if ("link_to_page".equals(type)) excluded++;
      } else if ("synced_block".equals(type) && body.path("synced_from").isNull()) text = "";
      else {
        gaps.add(new Gap(id, NotionSourceException.Code.UNSUPPORTED_BLOCK));
        return;
      }
      if (text == null) throw malformed();
      if (!text.isEmpty()) addDocument(id, text.getBytes(StandardCharsets.UTF_8));
      if (traverse && block.path("has_children").asBoolean()) walk(id, depth + 1);
    }

    private void addDocument(String id, byte[] text) {
      if (text.length > limits.maxTextBytes() - bytes) {
        Arrays.fill(text, (byte) 0);
        throw new NotionSourceException(NotionSourceException.Code.TEXT_LIMIT, 0);
      }
      bytes += text.length;
      documents.add(new Document(id, text));
    }

    private void gap(String blockId, NotionSourceException error) {
      gaps.add(new Gap(blockId, error.code()));
      if (error.retryAt() != null && (retryAt == null || error.retryAt().isAfter(retryAt)))
        retryAt = error.retryAt();
      if (Set.of(
              NotionSourceException.Code.RATE_LIMITED,
              NotionSourceException.Code.PROVIDER_ACCESS_BLOCKED,
              NotionSourceException.Code.SOURCE_UNAVAILABLE,
              NotionSourceException.Code.TIMEOUT,
              NotionSourceException.Code.REQUEST_LIMIT,
              NotionSourceException.Code.TEXT_LIMIT)
          .contains(error.code())) stopRequests = true;
    }
  }

  private record Document(String blockId, byte[] bytes) {}

  private static String cells(JsonNode cells) {
    if (!cells.isArray()) return null;
    var values = new ArrayList<String>();
    for (JsonNode cell : cells) {
      String text = NotionPageClient.richText(cell);
      if (text == null) return null;
      values.add(text);
    }
    return String.join("\t", values);
  }

  private static String sha(byte[] content) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
    } catch (NoSuchAlgorithmException error) {
      throw new IllegalStateException("DIGEST_UNAVAILABLE");
    }
  }

  private static String failureCode(List<Gap> gaps, Instant retryAt) {
    if (gaps.isEmpty()) return null;
    if (retryAt != null) {
      return gaps.stream().anyMatch(gap -> gap.code() == NotionSourceException.Code.RATE_LIMITED)
          ? "NOTION_RATE_LIMITED"
          : "NOTION_SOURCE_UNAVAILABLE";
    }
    return "NOTION_" + gaps.getFirst().code().name();
  }

  private static NotionSourceException malformed() {
    return new NotionSourceException(NotionSourceException.Code.MALFORMED_RESPONSE, 200);
  }
}
