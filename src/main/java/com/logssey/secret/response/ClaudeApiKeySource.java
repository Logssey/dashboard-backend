package com.logssey.secret.response;

import com.logssey.secret.aws.SecretAwsSourceCredentials;
import java.time.Duration;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;

/** Resolves the API's own AI credential with its workload identity. */
final class ClaudeApiKeySource {
    private ClaudeApiKeySource() { }

    static String read(String secretId, String region, String mode, String profile, String file) {
        if (secretId == null || !secretId.matches("[A-Za-z0-9/_+=.@:-]{1,512}")
                || region == null || !region.matches("[a-z]{2}(?:-[a-z]+)+-[0-9]+")) {
            throw unavailable();
        }
        protectLogging();
        try (var credentials = SecretAwsSourceCredentials.fromConfiguration(mode, profile, file);
             var client = SecretsManagerClient.builder().credentialsProvider(credentials)
                     .region(Region.of(region))
                     .overrideConfiguration(configuration -> configuration
                             .apiCallTimeout(Duration.ofSeconds(15))
                             .apiCallAttemptTimeout(Duration.ofSeconds(8)))
                     .build()) {
            return read(client, secretId);
        } catch (RuntimeException failure) {
            throw unavailable();
        }
    }

    static String read(SecretsManagerClient client, String secretId) {
        protectLogging();
        try {
            var response = client.getSecretValue(request -> request.secretId(secretId)
                    .versionStage("AWSCURRENT"));
            String value = response.secretString();
            if (value == null || value.isBlank() || value.length() > 4_096) throw unavailable();
            value = value.strip();
            if (value.chars().anyMatch(character -> character < 0x21 || character > 0x7e)) {
                throw unavailable();
            }
            return value;
        } catch (RuntimeException failure) {
            throw unavailable();
        }
    }

    private static void protectLogging() {
        for (String logger : java.util.List.of("software.amazon.awssdk.request",
                "software.amazon.awssdk.response", "org.apache.hc.client5.http.wire",
                "org.apache.http.wire")) {
            if (org.slf4j.LoggerFactory.getLogger(logger).isDebugEnabled()) throw unavailable();
        }
    }

    private static IllegalStateException unavailable() {
        return new IllegalStateException("CLAUDE_KEY_STORE_UNAVAILABLE");
    }
}
