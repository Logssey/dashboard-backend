package com.logssey.secret.connection.core;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import java.io.InputStream;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/** Fixed GitHub endpoints only, bounded metadata, no redirect or provider body in failures. */
public class GitHubInstallationClient {
    private final URI base;
    private final HttpClient http;
    private final JsonMapper json = new JsonMapper();

    public GitHubInstallationClient() {
        this(URI.create("https://api.github.com/"));
    }

    public GitHubInstallationClient(URI base) {
        if (!base.equals(URI.create("https://api.github.com/"))
                && !(base.getScheme().equals("http") && base.getHost().equals("127.0.0.1")))
            throw new IllegalArgumentException("GITHUB_ENDPOINT_INVALID");
        this.base = base;
        this.http =
                HttpClient.newBuilder()
                        .connectTimeout(Duration.ofSeconds(5))
                        .followRedirects(HttpClient.Redirect.NEVER)
                        .build();
    }

    public JsonNode repositories(GitHubSourceCredential credentials, int page) {
        return request(
                        "GET",
                        "installation/repositories?per_page=100&page=" + page,
                        token(credentials, null),
                        null)
                .path("repositories");
    }

    public JsonNode branches(GitHubSourceCredential credentials, String repository, int page) {
        return request(
                "GET",
                "repos/" + repository + "/branches?per_page=100&page=" + page,
                token(credentials, repository),
                null);
    }

    public void verifyRepository(GitHubSourceCredential credentials, String repository) {
        token(credentials, repository);
    }

    private String token(GitHubSourceCredential credentials, String repository) {
        Map<String, Object> data =
                repository == null
                        ? Map.of("permissions", Map.of("contents", "read"))
                        : Map.of(
                                "repositories",
                                List.of(repository.split("/")[1]),
                                "permissions",
                                Map.of("contents", "read"));
        var response =
                request(
                        "POST",
                        "app/installations/" + credentials.installationId() + "/access_tokens",
                        jwt(credentials),
                        json.writeValueAsString(data));
        String token = response.path("token").asText("");
        if (token.isBlank()
                || !"read".equals(response.path("permissions").path("contents").asText("")))
            throw unavailable();
        if (repository != null
                && (!response.path("repositories").isArray()
                        || response.path("repositories").size() != 1
                        || !repository.equalsIgnoreCase(
                                response.path("repositories").get(0).path("full_name").asText(""))))
            throw unavailable();
        return token;
    }

    private JsonNode request(String method, String path, String bearer, String body) {
        try {
            if (!System.getProperty("jdk.httpclient.HttpClient.log", "").isBlank())
                throw unavailable();
            var builder =
                    HttpRequest.newBuilder(base.resolve(path))
                            .timeout(Duration.ofSeconds(12))
                            .header("Accept", "application/vnd.github+json")
                            .header("X-GitHub-Api-Version", "2026-03-10")
                            .header("User-Agent", "logssey-source-connections")
                            .header("Authorization", "Bearer " + bearer);
            if (method.equals("POST"))
                builder.header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body));
            else builder.GET();
            HttpResponse<InputStream> response =
                    http.send(builder.build(), HttpResponse.BodyHandlers.ofInputStream());
            try (var stream = response.body()) {
                if (response.statusCode() != (method.equals("POST") ? 201 : 200))
                    throw unavailable();
                byte[] bytes = stream.readNBytes(1_048_577);
                try {
                    if (bytes.length > 1_048_576) throw unavailable();
                    return json.readTree(bytes);
                } finally {
                    java.util.Arrays.fill(bytes, (byte) 0);
                }
            }
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
            throw unavailable();
        } catch (Exception ignored) {
            throw unavailable();
        }
    }

    private String jwt(GitHubSourceCredential credentials) {
        try {
            long now = Instant.now().getEpochSecond();
            String header = base64(json.writeValueAsString(Map.of("alg", "RS256", "typ", "JWT")));
            String payload =
                    base64(
                            json.writeValueAsString(
                                    Map.of(
                                            "iat",
                                            now - 60,
                                            "exp",
                                            now + 540,
                                            "iss",
                                            credentials.appId())));
            String unsigned = header + "." + payload;
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(credentials.privateKey());
            signature.update(unsigned.getBytes(StandardCharsets.US_ASCII));
            return unsigned
                    + "."
                    + Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign());
        } catch (Exception ignored) {
            throw unavailable();
        }
    }

    public static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static String base64(String value) {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private static IllegalStateException unavailable() {
        return new IllegalStateException("GITHUB_SOURCE_ACCESS_UNAVAILABLE");
    }
}
