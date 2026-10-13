package com.logssey.secretworker.validation;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import com.logssey.secretworker.detection.SecretFindingNormalizer;
import com.logssey.secretworker.detector.GitleaksFinding;

import static org.assertj.core.api.Assertions.assertThat;

class AwsValidationHandoffTest {
    private static final String ID = "AKIA" + "ABCDEFGHIJKLMNOP";
    private static final String SECRET = "aB3/".repeat(10);
    private static final Instant NOW = Instant.parse("2026-10-14T00:00:00Z");

    @Test
    void exactNormalizedPairFeedsOnlyTheInMemoryValidator() {
        var normalizer = new SecretFindingNormalizer(new byte[32], "test-v1");
        byte[] content = ("AWS_ACCESS_KEY_ID=" + ID + "\nAWS_SECRET_ACCESS_KEY=" + SECRET + "\n")
                .getBytes(StandardCharsets.UTF_8);
        var findings = List.of(new GitleaksFinding("aws-access-token", 1, 1, 19, 38),
                new GitleaksFinding("generic-api-key", 2, 2, 1, 60));
        var inspection = normalizer.inspect(1, "repo/aws.txt", content, findings);
        assertThat(inspection.credentials()).hasSize(1);
        assertThat(inspection.awsCandidates()).hasSize(1);
        assertThat(inspection.awsCandidates().getFirst().credential())
                .isSameAs(inspection.credentials().getFirst());
        assertThat(inspection.credentials().getFirst().fingerprint()).hasSize(32);

        AtomicInteger calls = new AtomicInteger();
        var validator = new AwsCredentialValidator(true, Clock.fixed(NOW, ZoneOffset.UTC), key -> {
            calls.incrementAndGet();
            assertThat(key.accessKeyId()).isEqualTo(ID);
            assertThat(key.secretAccessKey()).isEqualTo(SECRET);
            assertThat(key.sessionToken()).isNull();
        });
        var result = validator.validate(inspection.awsCandidates().getFirst().material());
        assertThat(result.status()).isEqualTo(AwsValidationResult.Status.VALID);
        assertThat(calls).hasValue(1);
        assertThat(inspection.toString()).doesNotContain(ID, SECRET);
        assertThat(inspection.awsCandidates().toString()).doesNotContain(ID, SECRET);
        assertThat(result.toString()).doesNotContain(ID, SECRET);
    }

    @Test
    void temporaryKeyMissingSessionIsCandidateAndNeverCallsProvider() {
        String id = "ASIA" + "ABCDEFGHIJKLMNOP";
        byte[] content = ("AWS_ACCESS_KEY_ID=" + id + "\nAWS_SECRET_ACCESS_KEY=" + SECRET + "\n")
                .getBytes(StandardCharsets.UTF_8);
        var inspection = new SecretFindingNormalizer(new byte[32], "test-v1")
                .inspect(1, "repo/temp.env", content, List.of(
                        new GitleaksFinding("aws-access-token", 1, 1, 19, 38),
                        new GitleaksFinding("generic-api-key", 2, 2, 1, 60)));
        assertThat(inspection.credentials()).hasSize(1);
        assertThat(inspection.credentials().getFirst().componentState()).isEqualTo("CANDIDATE");
        assertThat(inspection.credentials().getFirst().fingerprint()).isNull();
        AtomicInteger calls = new AtomicInteger();
        var validator = new AwsCredentialValidator(true, Clock.fixed(NOW, ZoneOffset.UTC),
                key -> calls.incrementAndGet());
        var result = validator.validate(inspection.awsCandidates().getFirst().material());
        assertThat(result.status()).isEqualTo(AwsValidationResult.Status.UNCHECKED);
        assertThat(result.reason()).isEqualTo(AwsValidationResult.Reason.MISSING_SESSION_TOKEN);
        assertThat(calls).hasValue(0);
    }
}
