package com.logssey.secretworker.github;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Signature;
import java.time.Clock;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

import tools.jackson.databind.JsonNode;

/** Issues one repository-limited, read-only installation token per collection. */
public final class GitHubAppTokenProvider {
    private final long appId;
    private final long installationId;
    private final PrivateKey privateKey;
    private final GitHubRestClient api;
    private final Clock clock;

    public GitHubAppTokenProvider(GitHubAppCredentials credentials, GitHubRestClient api) {
        this(credentials.appId(), credentials.installationId(),
                GitHubPemKeyReader.read(credentials.privateKeyPath()), api, Clock.systemUTC());
    }

    GitHubAppTokenProvider(long appId, long installationId, PrivateKey privateKey,
                          GitHubRestClient api, Clock clock) {
        if (appId <= 0 || installationId <= 0) throw new IllegalArgumentException("Invalid GitHub App IDs");
        this.appId = appId;
        this.installationId = installationId;
        this.privateKey = Objects.requireNonNull(privateKey);
        this.api = Objects.requireNonNull(api);
        this.clock = Objects.requireNonNull(clock);
    }

    GitHubAppTokenProvider observed(com.logssey.secret.run.progress.core.ScanExecutionObserver observer) {
        return new GitHubAppTokenProvider(appId, installationId, privateKey, api.observed(observer), clock);
    }

    String tokenFor(GitHubApprovedScope scope) {
        String jwt = jwt();
        String request = api.json(Map.of("repositories", new String[]{scope.repository()},
                "permissions", Map.of("contents", "read")));
        JsonNode response = api.post("app/installations/" + installationId + "/access_tokens", jwt, request);
        String token = response.path("token").asText("");
        JsonNode repositories = response.path("repositories");
        JsonNode permissions = response.path("permissions");
        if (token.isBlank() || !repositories.isArray() || repositories.size() != 1
                || !repositories.get(0).path("full_name").asText("")
                .equalsIgnoreCase(scope.owner() + "/" + scope.repository())
                || !"read".equals(permissions.path("contents").asText(""))) {
            throw new GitHubSourceException(GitHubSourceException.Code.ACCESS_DENIED, 0, null);
        }
        return token;
    }

    private String jwt() {
        long now = clock.instant().getEpochSecond();
        String header = base64(api.json(Map.of("alg", "RS256", "typ", "JWT")));
        String payload = base64(api.json(Map.of("iat", now - 60, "exp", now + 540, "iss", appId)));
        String unsigned = header + "." + payload;
        try {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(unsigned.getBytes(StandardCharsets.US_ASCII));
            return unsigned + "." + Base64.getUrlEncoder().withoutPadding().encodeToString(signature.sign());
        } catch (java.security.GeneralSecurityException e) {
            throw new IllegalStateException("GitHub App signing failed");
        }
    }

    private static String base64(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }
}
