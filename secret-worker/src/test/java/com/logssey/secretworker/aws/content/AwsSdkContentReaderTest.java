package com.logssey.secretworker.aws.content;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import java.io.ByteArrayInputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.GetParameterRequest;
import software.amazon.awssdk.services.ssm.model.GetParameterResponse;
import software.amazon.awssdk.services.ssm.model.Parameter;

class AwsSdkContentReaderTest {
    private static final String ACCOUNT = "123456789012";
    private static final String REGION = "ap-northeast-2";

    @Test void secretAndParameterRequestsUseExactArnAndDecryption() {
        var secrets = mock(SecretsManagerClient.class);
        var ssm = mock(SsmClient.class);
        var s3 = mock(S3Client.class);
        var reader = reader(secrets, ssm, s3);
        String secretArn = "arn:aws:secretsmanager:" + REGION + ":" + ACCOUNT + ":secret:fixture-AbCdEf";
        var secretScope = scope("AWS_SECRETS_MANAGER_VALUE", "secrets-manager/secret/" + encode(secretArn));
        when(secrets.getSecretValue(any(GetSecretValueRequest.class))).thenReturn(
                GetSecretValueResponse.builder().secretString("synthetic test data").build());
        byte[] secret = reader.read(secretScope, 64);
        assertEquals("synthetic test data", new String(secret, StandardCharsets.UTF_8));
        Arrays.fill(secret, (byte) 0);
        var secretRequest = org.mockito.ArgumentCaptor.forClass(GetSecretValueRequest.class);
        verify(secrets).getSecretValue(secretRequest.capture());
        assertEquals(secretArn, secretRequest.getValue().secretId());
        assertEquals("AWSCURRENT", secretRequest.getValue().versionStage());

        String parameterArn = "arn:aws:ssm:" + REGION + ":" + ACCOUNT + ":parameter/local/fixture";
        var parameterScope = scope("AWS_SSM_PARAMETER_VALUE", "ssm/parameter/" + encode(parameterArn));
        when(ssm.getParameter(any(GetParameterRequest.class))).thenReturn(GetParameterResponse.builder()
                .parameter(Parameter.builder().value("synthetic test data").build()).build());
        byte[] parameter = reader.read(parameterScope, 64);
        Arrays.fill(parameter, (byte) 0);
        var parameterRequest = org.mockito.ArgumentCaptor.forClass(GetParameterRequest.class);
        verify(ssm).getParameter(parameterRequest.capture());
        assertEquals(parameterArn, parameterRequest.getValue().name());
        assertTrue(parameterRequest.getValue().withDecryption());
    }

    @Test void s3PreflightsSizeAndPinsGetToExpectedOwnerAndEtag() {
        var secrets = mock(SecretsManagerClient.class);
        var ssm = mock(SsmClient.class);
        var s3 = mock(S3Client.class);
        var reader = reader(secrets, ssm, s3);
        var object = scope("AWS_S3_OBJECT_CONTENT", "s3/object/fixture-bucket/" + encode("cfg/app.yaml"));
        when(s3.headObject(any(HeadObjectRequest.class))).thenReturn(HeadObjectResponse.builder()
                .contentLength(8L).eTag("\"etag\"").build());
        assertEquals(AwsContentReader.FailureCode.TOO_LARGE,
                assertThrows(AwsContentReader.ReadFailure.class, () -> reader.read(object, 7)).code());
        verify(s3, never()).getObject(any(GetObjectRequest.class));

        byte[] value = "fixture!".getBytes(StandardCharsets.UTF_8);
        when(s3.getObject(any(GetObjectRequest.class))).thenAnswer(invocation ->
                new ResponseInputStream<>(GetObjectResponse.builder().contentLength(8L).build(),
                        AbortableInputStream.create(new ByteArrayInputStream(value))));
        byte[] content = reader.read(object, 8);
        assertArrayEquals(value, content);
        Arrays.fill(content, (byte) 0);
        var head = org.mockito.ArgumentCaptor.forClass(HeadObjectRequest.class);
        var get = org.mockito.ArgumentCaptor.forClass(GetObjectRequest.class);
        verify(s3, times(2)).headObject(head.capture());
        verify(s3).getObject(get.capture());
        assertEquals(ACCOUNT, head.getValue().expectedBucketOwner());
        assertEquals(ACCOUNT, get.getValue().expectedBucketOwner());
        assertEquals("\"etag\"", get.getValue().ifMatch());
        assertEquals("cfg/app.yaml", get.getValue().key());
    }

    @Test void sdkProviderErrorsBecomeSafeCodesWithoutMessageOrCause() {
        var secrets = mock(SecretsManagerClient.class);
        var reader = reader(secrets, mock(SsmClient.class), mock(S3Client.class));
        String arn = "arn:aws:secretsmanager:" + REGION + ":" + ACCOUNT + ":secret:fixture-AbCdEf";
        when(secrets.getSecretValue(any(GetSecretValueRequest.class)))
                .thenThrow(S3Exception.builder().statusCode(403)
                        .message("synthetic sensitive response").build());
        var failure = assertThrows(AwsContentReader.ReadFailure.class,
                () -> reader.read(scope("AWS_SECRETS_MANAGER_VALUE", "secrets-manager/secret/" + encode(arn)), 64));
        assertEquals(AwsContentReader.FailureCode.ACCESS_DENIED, failure.code());
        assertFalse(failure.toString().contains("synthetic sensitive response"));
        assertNull(failure.getCause());
    }

    @Test void prefixListingUsesOwnerPrefixAndContinuationWithoutDelimiter() {
        var s3=mock(S3Client.class);
        var reader=reader(mock(SecretsManagerClient.class),mock(SsmClient.class),s3);
        when(s3.listObjectsV2(any(software.amazon.awssdk.services.s3.model.ListObjectsV2Request.class)))
                .thenReturn(software.amazon.awssdk.services.s3.model.ListObjectsV2Response.builder()
                        .isTruncated(true).nextContinuationToken("next")
                        .contents(software.amazon.awssdk.services.s3.model.S3Object.builder().key("cfg/sub/a.env").build()).build());
        var page=reader.list(scope("AWS_S3_OBJECT_CONTENT","s3/prefix/fixture-bucket/cfg%2F"),"previous");
        assertEquals("next",page.nextToken());
        assertEquals(java.util.List.of("cfg/sub/a.env"),page.keys());
        var capture=org.mockito.ArgumentCaptor.forClass(software.amazon.awssdk.services.s3.model.ListObjectsV2Request.class);
        verify(s3).listObjectsV2(capture.capture());
        assertEquals("cfg/",capture.getValue().prefix());
        assertEquals(ACCOUNT,capture.getValue().expectedBucketOwner());
        assertEquals("previous",capture.getValue().continuationToken());
        assertNull(capture.getValue().delimiter());
    }

    private static AwsSdkContentReader reader(SecretsManagerClient secrets, SsmClient ssm, S3Client s3) {
        return new AwsSdkContentReader(new AwsSdkContentReader.ClientFactory() {
            @Override public SecretsManagerClient secretsManager(String region) {
                assertEquals(REGION, region);
                return secrets;
            }
            @Override public SsmClient ssm(String region) {
                assertEquals(REGION, region);
                return ssm;
            }
            @Override public S3Client s3(String region) {
                assertEquals(REGION, region);
                return s3;
            }
        });
    }

    private static AwsContentScope scope(String type, String suffix) {
        return AwsContentScope.fromApprovedRef(type, "aws://" + ACCOUNT + "/" + REGION + "/" + suffix,
                "CURRENT_VALUE_ONLY");
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
