package com.logssey.secretworker.github;

import java.io.IOException;
import com.logssey.secret.run.progress.core.ScanExecutionObserver;
import static com.logssey.secret.run.progress.core.ScanExecutionObserver.*;
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
    private ScanExecutionObserver observer = ScanExecutionObserver.NONE;
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

    GitHubRestClient observed(ScanExecutionObserver observer) {
        var copy = new GitHubRestClient(apiBase, http);
        copy.observer = Objects.requireNonNull(observer);
        return copy;
    }

    private static Operation operation(String path) {
        if (path.contains("/git/ref/")) return Operation.GITHUB_REF_GET;
        if (path.contains("/git/commits/")) return Operation.GITHUB_COMMIT_GET;
        if (path.contains("/git/trees/")) return Operation.GITHUB_TREE_GET;
        if (path.contains("/git/blobs/")) return Operation.GITHUB_BLOB_GET;
        if (path.startsWith("app/installations/")) return Operation.GITHUB_TOKEN_EXCHANGE;
        return Operation.GITHUB_REPOSITORY_GET;
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
        Operation operation = operation(path);
        observer.record(Stage.COLLECTION, operation, Outcome.STARTED, null, null, null, null, null);
        long started = System.nanoTime();
        boolean responseObserved = false;
        try {
            HttpResponse<InputStream> response = http.send(request.build(), HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream stream = response.body()) {
                int status = response.statusCode();
                responseObserved = true;
                observer.record(Stage.COLLECTION, operation,
                        status >= 200 && status < 300 ? Outcome.COMPLETED : Outcome.FAILED,
                        status, status >= 200 && status < 300 ? null
                                : status == 429 ? "RATE_LIMITED"
                                : status == 401 || status == 403 ? "ACCESS_DENIED" : "OPERATION_FAILED",
                        null, null, ScanExecutionObserver.elapsed(started));
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
            if (!responseObserved) observer.record(Stage.COLLECTION, operation, Outcome.FAILED, null,
                    "NETWORK_ERROR", null, null, ScanExecutionObserver.elapsed(started));
            Thread.currentThread().interrupt();
            throw new GitHubSourceException(GitHubSourceException.Code.SOURCE_UNAVAILABLE, 0, null);
        } catch (IOException e) {
            if (!responseObserved) observer.record(Stage.COLLECTION, operation, Outcome.FAILED, null,
                    "NETWORK_ERROR", null, null, ScanExecutionObserver.elapsed(started));
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
