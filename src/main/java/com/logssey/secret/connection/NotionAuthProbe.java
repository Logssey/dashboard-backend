package com.logssey.secret.connection;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.regex.Pattern;

import com.logssey.secret.run.NotionScopeSql;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Checks that the read-only Notion integration can see the one approved page. Reads page
 * metadata only (never page content), and never returns or logs the token or response body.
 */
@Component
class NotionAuthProbe {
    private static final URI API_BASE = URI.create("https://api.notion.com/");
    private static final String NOTION_VERSION = "2026-03-11";
    private static final Pattern TOKEN = Pattern.compile("(?:ntn_|secret_)[A-Za-z0-9_]{20,200}");
    private static final int MAX_TOKEN_FILE_BYTES = 1_024;

    private final String tokenPath;
    private final URI apiBase;
    private final HttpClient http;

    @Autowired
    NotionAuthProbe(@Value("${SECRET_NOTION_TOKEN_PATH:}") String tokenPath) {
        this(tokenPath, API_BASE, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
                .version(HttpClient.Version.HTTP_1_1)
                .followRedirects(HttpClient.Redirect.NEVER).build());
    }

    NotionAuthProbe(String tokenPath, URI apiBase, HttpClient http) {
        this.tokenPath = tokenPath;
        this.apiBase = apiBase;
        this.http = http;
    }

    ConnectionProbeResult probe(SecretConnectionTestRepository.Scope scope) {
        if (!NotionScopeSql.approved(scope.contentType(), scope.historyLimit(), scope.approvedRef())) {
            return ConnectionProbeResult.failed("INVALID_APPROVED_SCOPE");
        }
        String pageId = NotionScopeSql.pageId(scope.approvedRef());
        String token = readToken();
        if (token == null) return ConnectionProbeResult.unavailable("NOTION_TOKEN_UNAVAILABLE");
        try {
            HttpRequest request = HttpRequest.newBuilder(apiBase.resolve("v1/pages/" + pageId))
                    .timeout(Duration.ofSeconds(10))
                    .header("Authorization", "Bearer " + token)
                    .header("Notion-Version", NOTION_VERSION)
                    .header("Accept", "application/json")
                    .header("User-Agent", "logssey-secret-connection-test")
                    .GET().build();
            HttpResponse<InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream body = response.body()) {
                int status = response.statusCode();
                if (status == 200) return ConnectionProbeResult.connected();
                if (status == 401 || status == 403 || status == 404) {
                    // 404 also means "page not shared with the integration".
                    return ConnectionProbeResult.failed("NOTION_ACCESS_DENIED");
                }
                if (status == 429) return ConnectionProbeResult.unavailable("NOTION_RATE_LIMITED");
                return ConnectionProbeResult.unavailable("NOTION_UNAVAILABLE");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return ConnectionProbeResult.unavailable("NOTION_UNAVAILABLE");
        } catch (IOException | RuntimeException e) {
            // The token and provider response never enter error responses or logs.
            return ConnectionProbeResult.unavailable("NOTION_UNAVAILABLE");
        }
    }

    private String readToken() {
        if (tokenPath == null || tokenPath.isBlank()) return null;
        try {
            Path path = Path.of(tokenPath);
            if (!Files.isRegularFile(path) || Files.size(path) > MAX_TOKEN_FILE_BYTES) return null;
            String token = Files.readString(path, StandardCharsets.UTF_8).strip();
            return TOKEN.matcher(token).matches() ? token : null;
        } catch (IOException | RuntimeException e) {
            return null;
        }
    }
}
