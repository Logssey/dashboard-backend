package com.logssey.secretworker.aws.content;

import static org.junit.jupiter.api.Assertions.*;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import com.logssey.secretworker.SecretJobFailure;
import com.logssey.secretworker.SecretJobFailureCode;

class AwsContentCollectorTest {
    private static final String ACCOUNT = "123456789012";
    private static final String REGION = "ap-northeast-2";
    private static final String SECRET_ARN = "arn:aws:secretsmanager:" + REGION + ":" + ACCOUNT
            + ":secret:local-fixture-AbCdEf";
    private static final String SECRET_REF = "aws://" + ACCOUNT + "/" + REGION
            + "/secrets-manager/secret/" + encoded(SECRET_ARN);

    @Test void noValueApiOrSinkCallWithoutSeparateOptIn() {
        var reads = new AtomicInteger();
        var sinks = new AtomicInteger();
        var collector = new AwsContentCollector((scope, maxBytes) -> {
            reads.incrementAndGet();
            return "synthetic".getBytes(StandardCharsets.UTF_8);
        });
        var result = collector.collect(secretScope(), false, 64, (source, bytes) -> sinks.incrementAndGet());
        assertEquals(AwsContentCollector.Status.FAILED, result.status());
        assertEquals(AwsContentCollector.GapCode.CONTENT_READ_DISABLED, result.gaps().getFirst());
        assertEquals(0, reads.get());
        assertEquals(0, sinks.get());
    }

    @Test void exactTextValueIsSynchronousAndZeroedAfterDetection() {
        byte[] value = "local synthetic fixture".getBytes(StandardCharsets.UTF_8);
        var held = new AtomicReference<byte[]>();
        var collector = new AwsContentCollector((scope, maxBytes) -> value);
        var result = collector.collect(secretScope(), true, 64, (source, bytes) -> {
            assertEquals(AwsContentScope.Kind.SECRETS_MANAGER, source.kind());
            assertEquals(value.length, source.byteCount());
            assertEquals("local synthetic fixture", new String(bytes, StandardCharsets.UTF_8));
            held.set(bytes);
        });
        assertEquals(AwsContentCollector.Status.SUCCEEDED, result.status());
        assertEquals(1, result.objectCount());
        assertTrue(Arrays.equals(new byte[value.length], held.get()));
        assertFalse(result.toString().contains("local-fixture"));
    }

    @Test void binaryOversizeAndProviderErrorsHaveOnlySafeCodes() {
        byte[] binary = new byte[]{1, 0, 2};
        var binaryResult = new AwsContentCollector((scope, max) -> binary)
                .collect(secretScope(), true, 64, (source, bytes) -> fail());
        assertEquals(AwsContentCollector.GapCode.NON_TEXT, binaryResult.gaps().getFirst());
        assertArrayEquals(new byte[3], binary);

        byte[] oversized = new byte[65];
        var oversizedResult = new AwsContentCollector((scope, max) -> oversized)
                .collect(secretScope(), true, 64, (source, bytes) -> fail());
        assertEquals(AwsContentCollector.GapCode.OBJECT_TOO_LARGE, oversizedResult.gaps().getFirst());
        assertArrayEquals(new byte[65], oversized);

        var errorResult = new AwsContentCollector((scope, max) -> {
            throw new IllegalStateException("local-fixture-secret-material");
        }).collect(secretScope(), true, 64, (source, bytes) -> fail());
        assertEquals(AwsContentCollector.GapCode.SOURCE_UNAVAILABLE, errorResult.gaps().getFirst());
        assertFalse(errorResult.toString().contains("local-fixture-secret-material"));
    }

    @Test void sourceExceptionCannotLeakValueAndBufferIsZeroed() {
        byte[] value = "local synthetic fixture".getBytes(StandardCharsets.UTF_8);
        var result = new AwsContentCollector((scope, max) -> value)
                .collect(secretScope(), true, 64, (source, bytes) -> {
                    throw new IllegalStateException("local synthetic fixture");
                });
        assertEquals(AwsContentCollector.GapCode.CONSUMER_FAILED, result.gaps().getFirst());
        assertArrayEquals(new byte[value.length], value);
        assertFalse(result.toString().contains("synthetic"));
    }

    @Test void lostLeaseEscapesConsumerBoundaryAndStillZeroesValue() {
        byte[] value = "local synthetic fixture".getBytes(StandardCharsets.UTF_8);
        var collector = new AwsContentCollector((scope, max) -> value);
        var error = assertThrows(SecretJobFailure.class, () -> collector.collect(secretScope(), true, 64,
                (source, bytes) -> {
                    throw new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
                }));
        assertEquals(SecretJobFailureCode.LEASE_EXPIRED, error.code());
        assertArrayEquals(new byte[value.length], value);
    }

    @Test void onlyExactValueScopesWithCurrentValueLimitAreAccepted() {
        assertEquals(AwsContentScope.Kind.SECRETS_MANAGER, secretScope().kind());
        assertThrows(IllegalArgumentException.class, () -> AwsContentScope.fromApprovedRef(
                "AWS_SECRETS_MANAGER_METADATA", SECRET_REF, "CURRENT_VALUE_ONLY"));
        assertThrows(IllegalArgumentException.class, () -> AwsContentScope.fromApprovedRef(
                "AWS_SECRETS_MANAGER_VALUE", SECRET_REF, null));
        assertThrows(IllegalArgumentException.class, () -> AwsContentScope.fromApprovedRef(
                "AWS_SECRETS_MANAGER_VALUE", "aws://" + ACCOUNT + "/" + REGION
                        + "/secrets-manager/all", "CURRENT_VALUE_ONLY"));
        assertThrows(IllegalArgumentException.class, () -> AwsContentScope.fromApprovedRef(
                "AWS_SECRETS_MANAGER_VALUE", SECRET_REF.replace("aws://" + ACCOUNT,
                        "aws://999999999999"),
                "CURRENT_VALUE_ONLY"));
        assertFalse(secretScope().toString().contains("local-fixture"));
    }

    @Test void ssmAndS3RefsRequireOneEncodedResource() {
        String parameter = "arn:aws:ssm:" + REGION + ":" + ACCOUNT + ":parameter/local/fixture";
        String ssm = "aws://" + ACCOUNT + "/" + REGION + "/ssm/parameter/" + encoded(parameter);
        assertEquals(parameter, AwsContentScope.fromApprovedRef("AWS_SSM_PARAMETER_VALUE", ssm,
                "CURRENT_VALUE_ONLY").resource());
        String object = "aws://" + ACCOUNT + "/" + REGION + "/s3/object/fixture-bucket/"
                + encoded("configs/app.yaml");
        assertEquals("configs/app.yaml", AwsContentScope.fromApprovedRef("AWS_S3_OBJECT_CONTENT", object,
                "CURRENT_VALUE_ONLY").objectKey());
        assertThrows(IllegalArgumentException.class, () -> AwsContentScope.fromApprovedRef(
                "AWS_S3_OBJECT_CONTENT", object.replace("%2F", "/"), "CURRENT_VALUE_ONLY"));
        assertThrows(IllegalArgumentException.class, () -> AwsContentScope.fromApprovedRef(
                "AWS_S3_OBJECT_CONTENT", "aws://" + ACCOUNT + "/" + REGION
                        + "/s3/object/fixture-bucket/" + "x".repeat(480), "CURRENT_VALUE_ONLY"));
    }

    private static AwsContentScope secretScope() {
        return AwsContentScope.fromApprovedRef("AWS_SECRETS_MANAGER_VALUE", SECRET_REF,
                "CURRENT_VALUE_ONLY");
    }

    private static String encoded(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
