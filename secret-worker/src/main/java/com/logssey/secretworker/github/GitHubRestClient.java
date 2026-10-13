package com.logssey.secretworker.github;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Calls only the fixed GitHub REST host in production; JSON-provided URLs are never followed. */
public final class GitHubRestClient {
    private static final URI GITHUB_API = URI.create("https://api.github.com/");
    private static final int MAX_TOKEN_RESPONSE_BYTES = 65_536;
    private final URI apiBase;
    private final HttpClient http;
    private final JsonMapper json = new JsonMapper();

    public GitHubRestClient() {
        this(GITHUB_API, HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(10)).build());
    }

    // Local HTTP server only in tests. Do not derive this value from a connection or source document.
    GitHubRestClient(URI apiBase, HttpClient http) {
        this.apiBase = Objects.requireNonNull(apiBase);
        this.http = Objects.requireNonNull(http);
        if (!apiBase.toString().endsWith("/") || apiBase.getRawQuery() != null || apiBase.getRawFragment() != null) {
            throw new IllegalArgumentException("Invalid API base URI");
        }
    }

    JsonNode get(String path, String bearer, int maxBytes) {
        return request(path, bearer, null, maxBytes);
    }

    JsonNode post(String path, String bearer, String body) {
        return request(path, bearer, body, MAX_TOKEN_RESPONSE_BYTES);
    }

    String json(Object value) {
        return json.writeValueAsString(value);
    }

    private JsonNode request(String path, String bearer, String body, int maxBytes) {
        if (path.startsWith("/") || path.contains("..") || path.contains("#") || path.contains("?")) {
            throw new IllegalArgumentException("Invalid GitHub API path");
        }
        URI target = apiBase.resolve(path);
        if (!target.getScheme().equals(apiBase.getScheme()) || !target.getAuthority().equals(apiBase.getAuthority())) {
            throw new IllegalArgumentException("Invalid GitHub API target");
        }
        HttpRequest.Builder request = HttpRequest.newBuilder(target).timeout(Duration.ofSeconds(30))
                .header("Accept", "application/vnd.github+json")
                .header("Authorization", "Bearer " + bearer)
                .header("X-GitHub-Api-Version", "2026-03-10")
                .header("User-Agent", "logssey-secret-worker");
        if (body == null) {
            request.GET();
        } else {
            request.header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
        }
        try {
            HttpResponse<InputStream> response = http.send(request.build(), HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream stream = response.body()) {
                int status = response.statusCode();
                if (status < 200 || status >= 300) {
                    throw error(status, response);
                }
                long declared = response.headers().firstValueAsLong("Content-Length").orElse(-1);
                if (declared > maxBytes) {
                    throw new GitHubSourceException(GitHubSourceException.Code.RESPONSE_TOO_LARGE, status, null);
                }
                byte[] bytes = stream.readNBytes(maxBytes + 1);
                if (bytes.length > maxBytes) {
                    throw new GitHubSourceException(GitHubSourceException.Code.RESPONSE_TOO_LARGE, status, null);
                }
                try {
                    return json.readTree(bytes);
                } catch (RuntimeException invalidJson) {
                    throw new GitHubSourceException(GitHubSourceException.Code.MALFORMED_RESPONSE, status, null);
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new GitHubSourceException(GitHubSourceException.Code.SOURCE_UNAVAILABLE, 0, null);
        } catch (IOException e) {
            throw new GitHubSourceException(GitHubSourceException.Code.SOURCE_UNAVAILABLE, 0, null);
        }
    }

    private GitHubSourceException error(int status, HttpResponse<?> response) {
        Duration retryAfter = response.headers().firstValue("Retry-After").flatMap(value -> {
            try {
                return java.util.Optional.of(Duration.ofSeconds(Long.parseLong(value)));
            } catch (NumberFormatException e) {
                return java.util.Optional.empty();
            }
        }).orElse(null);
        boolean exhausted = "0".equals(response.headers().firstValue("X-RateLimit-Remaining").orElse(null));
        GitHubSourceException.Code code = switch (status) {
            case 401, 403 -> retryAfter != null || exhausted ? GitHubSourceException.Code.RATE_LIMITED
                    : GitHubSourceException.Code.ACCESS_DENIED;
            case 404 -> GitHubSourceException.Code.SOURCE_UNAVAILABLE;
            case 429 -> GitHubSourceException.Code.RATE_LIMITED;
            default -> GitHubSourceException.Code.API_ERROR;
        };
        return new GitHubSourceException(code, status, retryAfter);
    }

    static String encodeSegment(String value) {
        StringBuilder result = new StringBuilder();
        for (byte b : value.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xff;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '~') {
                result.append((char) c);
            } else {
                result.append('%').append(Character.toUpperCase(Character.forDigit(c >> 4, 16)))
                        .append(Character.toUpperCase(Character.forDigit(c & 15, 16)));
            }
        }
        return result.toString();
    }
}
