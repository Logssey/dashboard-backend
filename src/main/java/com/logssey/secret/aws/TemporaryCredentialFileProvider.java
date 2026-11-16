package com.logssey.secret.aws;

import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

import tools.jackson.databind.json.JsonMapper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;

/** Rereads an atomically rotated workload-session file on every SDK credential resolution. */
public final class TemporaryCredentialFileProvider implements AwsCredentialsProvider {
    private final Path path;
    private final Clock clock;

    public TemporaryCredentialFileProvider(Path path) {
        this(path, Clock.systemUTC());
    }

    TemporaryCredentialFileProvider(Path path, Clock clock) {
        this.path = path.toAbsolutePath().normalize();
        this.clock = clock;
    }

    @Override
    public AwsCredentials resolveCredentials() {
        byte[] bytes = null;
        try (var input = Files.newInputStream(path)) {
            bytes = input.readNBytes(16_385);
            if (bytes.length > 16_384) throw unavailable();
            var value = new JsonMapper().readTree(bytes);
            if (!value.isObject() || value.path("Version").asInt(0) != 1) throw unavailable();
            String access = value.path("AccessKeyId").asText("");
            String secret = value.path("SecretAccessKey").asText("");
            String session = value.path("SessionToken").asText("");
            Instant expires = Instant.parse(value.path("Expiration").asText(""));
            if (!access.matches("[A-Z0-9]{16,128}")
                    || secret.length() < 16
                    || secret.length() > 256
                    || session.isBlank()
                    || session.length() > 8192
                    || !expires.isAfter(clock.instant().plusSeconds(30))) throw unavailable();
            return AwsSessionCredentials.create(access, secret, session);
        } catch (Exception ignored) {
            // Provider/parser errors must never expose the file, payload, or a credential value.
            throw unavailable();
        } finally {
            if (bytes != null) Arrays.fill(bytes, (byte) 0);
        }
    }

    private static IllegalStateException unavailable() {
        return new IllegalStateException("AWS_WORKLOAD_CREDENTIALS_UNAVAILABLE");
    }

    @Override
    public String toString() {
        return "TemporaryCredentialFileProvider[redacted]";
    }
}
