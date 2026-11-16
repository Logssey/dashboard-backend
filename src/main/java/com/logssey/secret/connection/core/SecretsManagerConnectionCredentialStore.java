package com.logssey.secret.connection.core;

import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.ResourceExistsException;

import java.time.Duration;

public final class SecretsManagerConnectionCredentialStore implements ConnectionCredentialStore {
    private final SecretsManagerClient client;
    private final String prefix;

    public SecretsManagerConnectionCredentialStore(
            AwsCredentialsProvider credentials, String region, String prefix) {
        if (prefix == null || !prefix.matches("[A-Za-z0-9/_+=.@-]{1,150}/"))
            throw new IllegalArgumentException("SOURCE_SECRET_PREFIX_INVALID");
        this.prefix = prefix;
        this.client =
                SecretsManagerClient.builder()
                        .credentialsProvider(credentials)
                        .region(Region.of(region))
                        .overrideConfiguration(
                                c ->
                                        c.apiCallTimeout(Duration.ofSeconds(15))
                                                .apiCallAttemptTimeout(Duration.ofSeconds(8)))
                        .build();
    }

    SecretsManagerConnectionCredentialStore(SecretsManagerClient client, String prefix) {
        if (prefix == null || !prefix.matches("[A-Za-z0-9/_+=.@-]{1,150}/"))
            throw new IllegalArgumentException("SOURCE_SECRET_PREFIX_INVALID");
        this.client = client;
        this.prefix = prefix;
    }

    @Override
    public Reference put(String name, String token, String payload) {
        validate(name);
        protectLogging();
        try {
            try {
                var response =
                        client.createSecret(
                                r ->
                                        r.name(name)
                                                .clientRequestToken(token)
                                                .secretString(payload)
                                                .description(
                                                        "Logssey source connection credential"));
                if (!token.equals(response.versionId())) throw new IllegalStateException();
                return new Reference(name, response.versionId());
            } catch (ResourceExistsException exists) {
                var response =
                        client.putSecretValue(
                                r ->
                                        r.secretId(name)
                                                .clientRequestToken(token)
                                                .secretString(payload));
                if (!token.equals(response.versionId())) throw new IllegalStateException();
                return new Reference(name, response.versionId());
            }
        } catch (RuntimeException ignored) {
            throw new IllegalStateException("SOURCE_CREDENTIAL_STORAGE_UNAVAILABLE");
        }
    }

    @Override
    public String get(Reference ref) {
        validate(ref.secretName());
        if (ref.versionId() == null || !ref.versionId().matches("[0-9a-f]{64}"))
            throw new IllegalArgumentException("SOURCE_SECRET_VERSION_INVALID");
        protectLogging();
        try {
            var response =
                    client.getSecretValue(
                            r -> r.secretId(ref.secretName()).versionId(ref.versionId()));
            if (!ref.versionId().equals(response.versionId())
                    || response.secretString() == null
                    || response.secretString().length() > 40_000) throw new IllegalStateException();
            return response.secretString();
        } catch (RuntimeException ignored) {
            throw new IllegalStateException("SOURCE_CREDENTIAL_STORAGE_UNAVAILABLE");
        }
    }

    @Override
    public java.time.Instant scheduleDeletion(String name) {
        validate(name);
        protectLogging();
        try {
            var response = client.deleteSecret(r -> r.secretId(name).recoveryWindowInDays(7L));
            if (response.deletionDate() == null) throw new IllegalStateException();
            return response.deletionDate();
        } catch (RuntimeException ignored) {
            throw new IllegalStateException("SOURCE_CREDENTIAL_DELETION_UNAVAILABLE");
        }
    }

    @Override
    public void restore(String name) {
        validate(name);
        protectLogging();
        try {
            if (client.describeSecret(r -> r.secretId(name)).deletedDate() != null)
                client.restoreSecret(r -> r.secretId(name));
        } catch (RuntimeException ignored) {
            throw new IllegalStateException("SOURCE_CREDENTIAL_RESTORE_UNAVAILABLE");
        }
    }

    private static void protectLogging() {
        if (org.slf4j.LoggerFactory.getLogger("software.amazon.awssdk.request").isDebugEnabled()
                || org.slf4j.LoggerFactory.getLogger("org.apache.hc.client5.http.wire")
                        .isDebugEnabled()
                || org.slf4j.LoggerFactory.getLogger("org.apache.http.wire").isDebugEnabled())
            throw new IllegalStateException("SOURCE_CREDENTIAL_WIRE_LOGGING_FORBIDDEN");
    }

    private void validate(String name) {
        if (name == null
                || !name.startsWith(prefix)
                || name.length() > 512
                || !name.matches("[A-Za-z0-9/_+=.@-]+"))
            throw new IllegalArgumentException("SOURCE_SECRET_REFERENCE_INVALID");
    }

    @Override
    public void close() {
        client.close();
    }
}
