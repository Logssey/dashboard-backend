package com.logssey.secret.aws;

import static org.assertj.core.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;

import java.nio.file.*;
import java.time.*;

class TemporaryCredentialFileProviderTest {
    @TempDir Path directory;
    private final Instant now = Instant.parse("2026-11-17T00:00:00Z");

    @Test
    void rereadsRotatedSessionAndNeverCachesThePreviousKey() throws Exception {
        Path file = directory.resolve("credentials.json");
        var provider = new TemporaryCredentialFileProvider(file, Clock.fixed(now, ZoneOffset.UTC));
        Files.writeString(file, session("ASIA0000000000000001", now.plusSeconds(3600)));
        assertThat(provider.resolveCredentials().accessKeyId()).isEqualTo("ASIA0000000000000001");
        Files.writeString(file, session("ASIA0000000000000002", now.plusSeconds(3600)));
        assertThat(provider.resolveCredentials().accessKeyId()).isEqualTo("ASIA0000000000000002");
        assertThat(provider.resolveCredentials()).isInstanceOf(AwsSessionCredentials.class);
        assertThat(provider.toString()).doesNotContain(file.toString(), "ASIA");
    }

    @Test
    void expiredMalformedAndMissingFilesFailClosedWithSafeErrors() throws Exception {
        Path file = directory.resolve("credentials.json");
        var provider = new TemporaryCredentialFileProvider(file, Clock.fixed(now, ZoneOffset.UTC));
        assertThatThrownBy(provider::resolveCredentials)
                .hasMessage("AWS_WORKLOAD_CREDENTIALS_UNAVAILABLE")
                .hasNoCause();
        Files.writeString(file, session("ASIA0000000000000001", now.minusSeconds(1)));
        assertThatThrownBy(provider::resolveCredentials)
                .hasMessage("AWS_WORKLOAD_CREDENTIALS_UNAVAILABLE")
                .hasNoCause();
        Files.writeString(file, "{\"SecretAccessKey\":\"private-synthetic-material\"");
        assertThatThrownBy(provider::resolveCredentials)
                .hasMessage("AWS_WORKLOAD_CREDENTIALS_UNAVAILABLE")
                .hasNoCause();
    }

    @Test
    void explicitFileIsWorkloadOnlyAndNeverFallsBack() {
        assertThatThrownBy(
                        () ->
                                SecretAwsSourceCredentials.fromConfiguration(
                                        "PROFILE", "personal", "missing"))
                .hasMessage("AWS_WORKLOAD_FILE_CONFIGURATION_INVALID");
        assertThatThrownBy(
                        () ->
                                SecretAwsSourceCredentials.fromConfiguration(
                                        "WORKLOAD", "personal", "missing"))
                .hasMessage("AWS_WORKLOAD_FILE_CONFIGURATION_INVALID");
        try (var source =
                SecretAwsSourceCredentials.fromConfiguration(
                        "WORKLOAD", "", directory.resolve("missing").toString())) {
            assertThat(source.authRef()).isEqualTo("aws-workload:default");
            assertThatThrownBy(source::resolveCredentials)
                    .hasMessage("AWS_WORKLOAD_CREDENTIALS_UNAVAILABLE");
        }
    }

    private String session(String access, Instant expires) {
        return "{\"Version\":1,\"AccessKeyId\":\""
                + access
                + "\",\"SecretAccessKey\":\"synthetic-private-value-00000000000000000000\","
                + "\"SessionToken\":\"synthetic-session-token\",\"Expiration\":\""
                + expires
                + "\"}";
    }
}
