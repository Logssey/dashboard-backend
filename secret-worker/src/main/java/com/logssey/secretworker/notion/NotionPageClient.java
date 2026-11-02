package com.logssey.secretworker.notion;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Supplier;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Read-only calls to the fixed Notion host. Only two endpoints are used:
 * GET /v1/pages/{id} (metadata: version, trash state, web publication) and
 * GET /v1/pages/{id}/markdown (the page's own text). URLs inside responses are never followed.
 */
public final class NotionPageClient {
    public static final String API_VERSION = "2026-03-11";
    private static final URI NOTION_API = URI.create("https://api.notion.com/");
    static final int MAX_METADATA_BYTES = 262_144;
    static final int MAX_MARKDOWN_RESPONSE_BYTES = 2_097_152;

    private final URI apiBase;
    private final HttpClient http;
    private final Supplier<String> token;
    private final JsonMapper json = new JsonMapper();

    /** The connection token file is read for each call so a rotated token takes effect without restart. */
    public NotionPageClient(Path tokenPath) {
        this(NOTION_API, HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10))
                .build(), () -> readToken(tokenPath));
    }

    // Local HTTP server only in tests. Never derived from a connection, finding or page content.
    NotionPageClient(URI apiBase, HttpClient http, Supplier<String> token) {
        this.apiBase = Objects.requireNonNull(apiBase);
        this.http = Objects.requireNonNull(http);
        this.token = Objects.requireNonNull(token);
        boolean official = NOTION_API.equals(apiBase);
        boolean local = "http".equals(apiBase.getScheme()) && "127.0.0.1".equals(apiBase.getHost());
        if (!(official || local) || !apiBase.toString().endsWith("/")
                || apiBase.getRawQuery() != null || apiBase.getRawFragment() != null) {
            throw new IllegalArgumentException("UNREGISTERED_NOTION_ENDPOINT");
        }
    }

    public record PageMetadata(String pageId, String lastEditedTime, boolean inTrash,
                               boolean publishedToWeb) { }

    public record PageMarkdown(byte[] utf8, boolean truncated) {
        @Override public String toString() {
            return "PageMarkdown[bytes=" + utf8.length + ", truncated=" + truncated + "]";
        }
    }

    public PageMetadata metadata(NotionApprovedScope scope) {
        JsonNode page = get("v1/pages/" + scope.pageId(), MAX_METADATA_BYTES);
        String id = page.path("id").asText("").replace("-", "");
        String lastEdited = page.path("last_edited_time").asText("");
        if (!"page".equals(page.path("object").asText(""))
                || !id.equals(scope.pageId().replace("-", ""))
                || lastEdited.isBlank() || lastEdited.length() > 64) {
            throw new NotionSourceException(NotionSourceException.Code.MALFORMED_RESPONSE, 200);
        }
        boolean trashed = page.path("in_trash").asBoolean(false) || page.path("archived").asBoolean(false);
        // Notion: public_url is the published page URL, otherwise null. Only its presence is kept.
        JsonNode publicUrl = page.path("public_url");
        boolean published = publicUrl.isTextual() && !publicUrl.asText("").isBlank();
        return new PageMetadata(scope.pageId(), lastEdited, trashed, published);
    }

    public PageMarkdown markdown(NotionApprovedScope scope) {
        JsonNode page = get("v1/pages/" + scope.pageId() + "/markdown", MAX_MARKDOWN_RESPONSE_BYTES);
        JsonNode markdown = page.path("markdown");
        if (!markdown.isTextual()) {
            throw new NotionSourceException(NotionSourceException.Code.MALFORMED_RESPONSE, 200);
        }
        boolean truncated = page.path("truncated").asBoolean(false)
                || page.path("unknown_block_ids").isArray() && !page.path("unknown_block_ids").isEmpty();
        return new PageMarkdown(markdown.asText("").getBytes(StandardCharsets.UTF_8), truncated);
    }

    private JsonNode get(String path, int maxBytes) {
        URI target = apiBase.resolve(path);
        if (!target.getScheme().equals(apiBase.getScheme())
                || !target.getAuthority().equals(apiBase.getAuthority())) {
            throw new IllegalArgumentException("Invalid Notion API target");
        }
        String bearer = token.get();
        HttpRequest request = HttpRequest.newBuilder(target)
                .timeout(Duration.ofSeconds(30))
                .header("Authorization", "Bearer " + bearer)
                .header("Notion-Version", API_VERSION)
                .header("User-Agent", "logssey-secret-worker")
                .GET()
                .build();
        try {
            HttpResponse<InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream stream = response.body()) {
                int status = response.statusCode();
                if (status != 200) {
                    throw error(status);
                }
                long declared = response.headers().firstValueAsLong("Content-Length").orElse(-1);
                if (declared > maxBytes) {
                    throw new NotionSourceException(NotionSourceException.Code.RESPONSE_TOO_LARGE, status);
                }
                byte[] bytes = stream.readNBytes(maxBytes + 1);
                try {
                    if (bytes.length > maxBytes) {
                        throw new NotionSourceException(NotionSourceException.Code.RESPONSE_TOO_LARGE, status);
                    }
                    try {
                        return json.readTree(bytes);
                    } catch (RuntimeException invalidJson) {
                        throw new NotionSourceException(NotionSourceException.Code.MALFORMED_RESPONSE, status);
                    }
                } finally {
                    Arrays.fill(bytes, (byte) 0);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new NotionSourceException(NotionSourceException.Code.UNAVAILABLE, 0);
        } catch (IOException e) {
            throw new NotionSourceException(NotionSourceException.Code.UNAVAILABLE, 0);
        }
    }

    private static NotionSourceException error(int status) {
        // The response body may quote the request; it is not read for errors.
        NotionSourceException.Code code = switch (status) {
            case 401, 403 -> NotionSourceException.Code.ACCESS_DENIED;
            case 404 -> NotionSourceException.Code.NOT_FOUND;
            case 429 -> NotionSourceException.Code.RATE_LIMITED;
            default -> status >= 500 ? NotionSourceException.Code.UNAVAILABLE
                    : NotionSourceException.Code.MALFORMED_RESPONSE;
        };
        return new NotionSourceException(code, status);
    }

    private static String readToken(Path path) {
        byte[] bytes = null;
        try {
            bytes = Files.readAllBytes(path);
            String value = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(bytes)).toString().strip();
            if (!value.matches("(ntn_|secret_)[A-Za-z0-9_]{20,200}")) {
                throw new NotionSourceException(NotionSourceException.Code.TOKEN_UNAVAILABLE, 0);
            }
            return value;
        } catch (IOException e) {
            throw new NotionSourceException(NotionSourceException.Code.TOKEN_UNAVAILABLE, 0);
        } finally {
            if (bytes != null) Arrays.fill(bytes, (byte) 0);
        }
    }

    @Override
    public String toString() {
        return "NotionPageClient[token=REDACTED]";
    }
}
