package com.logssey.secretworker.validation;

import java.net.URI;
import java.time.Duration;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;

/** Signs GetCallerIdentity with the supplied pair, never with the default credential chain. */
final class AwsStsCaller implements AwsCredentialValidator.StsCaller {
    private static final URI STS_ENDPOINT = URI.create("https://sts.us-east-1.amazonaws.com");
    private static final Duration CALL_TIMEOUT = Duration.ofSeconds(8);

    private final URI endpoint;

    AwsStsCaller() {
        this(STS_ENDPOINT);
    }

    // Only used by loopback tests. The production constructor pins the official STS endpoint.
    AwsStsCaller(URI endpoint) {
        this.endpoint = endpoint;
    }

    @Override
    public void getCallerIdentity(AwsKeyMaterial key) {
        AwsCredentials credentials = key.sessionToken() == null || key.sessionToken().isBlank()
                ? AwsBasicCredentials.create(key.accessKeyId(), key.secretAccessKey())
                : AwsSessionCredentials.create(key.accessKeyId(), key.secretAccessKey(), key.sessionToken());

        try (StsClient sts = StsClient.builder()
                .region(Region.US_EAST_1)
                .endpointOverride(endpoint)
                .credentialsProvider(StaticCredentialsProvider.create(credentials))
                .overrideConfiguration(config -> config.apiCallTimeout(CALL_TIMEOUT))
                .build()) {
            sts.getCallerIdentity();
        }
    }
}
