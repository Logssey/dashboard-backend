package com.logssey.secretworker.github;

import java.nio.file.Path;

/** An operator-provided reference to the App key. Never store the PEM or an installation token in the DB. */
public record GitHubAppCredentials(long appId, long installationId, Path privateKeyPath) {
    public GitHubAppCredentials {
        if (appId <= 0 || installationId <= 0 || privateKeyPath == null) {
            throw new IllegalArgumentException("Invalid GitHub App credentials reference");
        }
    }
}
