package com.logssey.secret.connection;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Probes the configured GitHub App's access to one approved repository; never fetches contents. */
@Component
class GitHubAuthProbe {
    private static final Pattern SCOPE = Pattern.compile(
            "^github://([A-Za-z0-9-]{1,39})/([A-Za-z0-9_.-]{1,100})/[^/?#]+/(?:[^/?#]+/)+$");
    private static final URI API_BASE = URI.create("https://api.github.com/");
    private static final int MAX_RESPONSE_BYTES = 65_536;

    private final long appId;
    private final long installationId;
    private final String privateKeyPath;
    private final URI apiBase;
    private final HttpClient http;
    private final Clock clock;
    private final JsonMapper json = new JsonMapper();

    @Autowired
    GitHubAuthProbe(@Value("${SECRET_GITHUB_APP_ID:0}") long appId,
                    @Value("${SECRET_GITHUB_INSTALLATION_ID:0}") long installationId,
                    @Value("${SECRET_GITHUB_PRIVATE_KEY_PATH:}") String privateKeyPath) {
        this(appId, installationId, privateKeyPath, API_BASE,
                HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5))
                        .followRedirects(HttpClient.Redirect.NEVER).build(), Clock.systemUTC());
    }

    GitHubAuthProbe(long appId, long installationId, String privateKeyPath,
                    URI apiBase, HttpClient http, Clock clock) {
        this.appId = appId;
        this.installationId = installationId;
        this.privateKeyPath = privateKeyPath;
        this.apiBase = apiBase;
        this.http = http;
        this.clock = clock;
    }

    ConnectionProbeResult probe(SecretConnectionTestRepository.Scope scope) {
        if (!"GITHUB_REPOSITORY_FILES".equals(scope.contentType())
                || !"CURRENT_COMMIT_ONLY".equals(scope.historyLimit())
                || scope.approvedRef() == null) return ConnectionProbeResult.failed("INVALID_APPROVED_SCOPE");
        var match = SCOPE.matcher(scope.approvedRef());
        if (!match.matches() || match.group(1).startsWith("-") || match.group(1).endsWith("-")
                || match.group(2).equals(".") || match.group(2).equals("..")) {
            return ConnectionProbeResult.failed("INVALID_APPROVED_SCOPE");
        }
        if (appId <= 0 || installationId <= 0 || privateKeyPath == null || privateKeyPath.isBlank()) {
            return ConnectionProbeResult.unavailable("GITHUB_APP_UNAVAILABLE");
        }
        String owner = match.group(1);
        String repository = match.group(2);
        PrivateKey key;
        try {
            key = GitHubPrivateKeyReader.read(Path.of(privateKeyPath));
        } catch (RuntimeException e) {
            return ConnectionProbeResult.unavailable("GITHUB_APP_UNAVAILABLE");
        }
        try {
            String bearer = jwt(key);
            String body = json.writeValueAsString(Map.of("repositories", new String[]{repository},
                    "permissions", Map.of("contents", "read")));
            HttpRequest request = HttpRequest.newBuilder(apiBase.resolve(
                            "app/installations/" + installationId + "/access_tokens"))
                    .timeout(Duration.ofSeconds(10))
                    .header("Accept", "application/vnd.github+json")
                    .header("Authorization", "Bearer " + bearer)
                    .header("X-GitHub-Api-Version", "2026-03-10")
                    .header("User-Agent", "logssey-secret-connection-test")
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8)).build();
            HttpResponse<InputStream> response = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
            try (InputStream stream = response.body()) {
                int status = response.statusCode();
                if (status == 429 || (status == 403 && "0".equals(response.headers()
                        .firstValue("X-RateLimit-Remaining").orElse(null)))) {
                    return ConnectionProbeResult.unavailable("GITHUB_RATE_LIMITED");
                }
                if (status == 401 || status == 403 || status == 404) {
                    return ConnectionProbeResult.failed("GITHUB_ACCESS_DENIED");
                }
                if (status != 201 || response.headers().firstValueAsLong("Content-Length")
                        .orElse(0) > MAX_RESPONSE_BYTES) {
                    return ConnectionProbeResult.unavailable("GITHUB_UNAVAILABLE");
                }
                byte[] bytes = stream.readNBytes(MAX_RESPONSE_BYTES + 1);
                if (bytes.length > MAX_RESPONSE_BYTES) {
                    return ConnectionProbeResult.unavailable("GITHUB_UNAVAILABLE");
                }
                JsonNode payload = json.readTree(bytes);
                JsonNode repositories = payload.path("repositories");
                if (payload.path("token").asText("").isBlank() || !repositories.isArray()
                        || repositories.size() != 1 || !repositories.get(0).path("full_name")
                        .asText("").equalsIgnoreCase(owner + "/" + repository)
                        || !"read".equals(payload.path("permissions").path("contents").asText(""))) {
                    return ConnectionProbeResult.failed("GITHUB_ACCESS_DENIED");
                }
                return ConnectionProbeResult.connected();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return ConnectionProbeResult.unavailable("GITHUB_UNAVAILABLE");
        } catch (IOException e) {
            return ConnectionProbeResult.unavailable("GITHUB_UNAVAILABLE");
        } catch (RuntimeException e) {
            // Bearer tokens and provider response bodies never enter error responses or logs.
            return ConnectionProbeResult.unavailable("GITHUB_UNAVAILABLE");
        }
    }

    private String jwt(PrivateKey key) {
        long now = clock.instant().getEpochSecond();
        String header = base64(json.writeValueAsString(Map.of("alg", "RS256", "typ", "JWT")));
        String payload = base64(json.writeValueAsString(Map.of(
                "iat", now - 60, "exp", now + 540, "iss", appId)));
        String unsigned = header + "." + payload;
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(key);
            signature.update(unsigned.getBytes(StandardCharsets.US_ASCII));
            return unsigned + "." + Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(signature.sign());
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalArgumentException("GITHUB_SIGNING_UNAVAILABLE");
        }
    }

    private static String base64(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
