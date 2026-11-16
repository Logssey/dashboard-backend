package com.logssey.secret.connection;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public final class SecretConnectionManagementContracts {
    private SecretConnectionManagementContracts() {}

    public record GitHubCredential(
            Long appId,
            Long installationId,
            @JsonProperty(access = JsonProperty.Access.WRITE_ONLY) String privateKey) {
        @Override
        public String toString() {
            return "GitHubCredential[redacted]";
        }
    }

    public record Create(
            String provider,
            String displayName,
            String idempotencyKey,
            GitHubCredential githubCredential) {}

    public record SettingsChange(
            Long expectedScopeVersion,
            String displayName,
            String status,
            GitHubCredential githubCredential) {}

    public record GitHubTarget(String repository, String branch, String path) {}

    public record AwsTarget(String kind, String region) {}

    public record TargetsChange(
            Long expectedScopeVersion,
            List<GitHubTarget> githubTargets,
            List<AwsTarget> awsTargets) {}
}
