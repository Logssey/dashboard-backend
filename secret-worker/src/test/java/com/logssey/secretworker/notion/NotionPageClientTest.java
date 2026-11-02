package com.logssey.secretworker.notion;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class NotionPageClientTest {
    private static final String TOKEN = "ntn_" + "12345678901" + "COLLECTOR".repeat(3) + "ABCDEFGH";
    private static final NotionApprovedScope SCOPE =
            NotionApprovedScope.fromApprovedRef("notion://pages/0123456789abcdef0123456789abcdef", "CURRENT_VERSION_ONLY");
    private HttpServer server;
    private int status = 200;
    private String pageBody = "{\"object\":\"page\",\"id\":\"01234567-89ab-cdef-0123-456789abcdef\","
            + "\"last_edited_time\":\"2026-11-02T00:00:00.000Z\",\"in_trash\":false,"
            + "\"public_url\":\"https://example.notion.site/page\"}";
    private String markdownBody = "{\"object\":\"page_markdown\",\"markdown\":\"NOTION_TOKEN=abc\",\"truncated\":false}";
    private final List<String> paths = new ArrayList<>();
    private NotionPageClient client;

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            paths.add(exchange.getRequestURI().getPath());
            assertThat(exchange.getRequestHeaders().getFirst("Authorization")).isEqualTo("Bearer " + TOKEN);
            assertThat(exchange.getRequestHeaders().getFirst("Notion-Version")).isEqualTo(NotionPageClient.API_VERSION);
            String body = exchange.getRequestURI().getPath().endsWith("/markdown") ? markdownBody : pageBody;
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        client = new NotionPageClient(URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/"),
                HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).build(), () -> TOKEN);
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    @Test
    void readsOnlyThePageMetadataAndItsOwnMarkdown() {
        var metadata = client.metadata(SCOPE);
        assertThat(metadata.publishedToWeb()).isTrue();
        assertThat(metadata.inTrash()).isFalse();
        assertThat(metadata.lastEditedTime()).isEqualTo("2026-11-02T00:00:00.000Z");
        var markdown = client.markdown(SCOPE);
        assertThat(new String(markdown.utf8(), StandardCharsets.UTF_8)).isEqualTo("NOTION_TOKEN=abc");
        assertThat(markdown.truncated()).isFalse();
        assertThat(markdown.toString()).doesNotContain("NOTION_TOKEN");
        assertThat(paths).containsExactly("/v1/pages/01234567-89ab-cdef-0123-456789abcdef",
                "/v1/pages/01234567-89ab-cdef-0123-456789abcdef/markdown");
    }

    @Test
    void unpublishedPageHasNoPublicUrl() {
        pageBody = pageBody.replace("\"https://example.notion.site/page\"", "null");
        assertThat(client.metadata(SCOPE).publishedToWeb()).isFalse();
    }

    @Test
    void truncatedOrPartlyUnreadableMarkdownIsReported() {
        markdownBody = "{\"markdown\":\"x\",\"truncated\":false,\"unknown_block_ids\":[\"b1\"]}";
        assertThat(client.markdown(SCOPE).truncated()).isTrue();
    }

    @Test
    void aDifferentPageIdInTheResponseIsRejected() {
        pageBody = pageBody.replace("01234567-89ab-cdef-0123-456789abcdef", "ffffffff-89ab-cdef-0123-456789abcdef");
        assertThatThrownBy(() -> client.metadata(SCOPE)).isInstanceOf(NotionSourceException.class)
                .extracting(e -> ((NotionSourceException) e).code())
                .isEqualTo(NotionSourceException.Code.MALFORMED_RESPONSE);
    }

    @Test
    void providerErrorsBecomeSafeCodes() {
        int[][] cases = {{401, 0}, {403, 0}, {404, 1}, {429, 2}, {503, 3}};
        NotionSourceException.Code[] expected = {NotionSourceException.Code.ACCESS_DENIED,
                NotionSourceException.Code.NOT_FOUND, NotionSourceException.Code.RATE_LIMITED,
                NotionSourceException.Code.UNAVAILABLE};
        for (int[] c : cases) {
            status = c[0];
            assertThatThrownBy(() -> client.metadata(SCOPE)).as("status " + c[0])
                    .isInstanceOf(NotionSourceException.class)
                    .extracting(e -> ((NotionSourceException) e).code()).isEqualTo(expected[c[1]]);
        }
    }

    @Test
    void onlyTheOfficialHostOrALocalTestServerIsAllowed() {
        assertThatThrownBy(() -> new NotionPageClient(URI.create("https://evil.example/"),
                HttpClient.newHttpClient(), () -> TOKEN)).isInstanceOf(IllegalArgumentException.class);
        assertThat(client.toString()).doesNotContain(TOKEN);
    }
}
