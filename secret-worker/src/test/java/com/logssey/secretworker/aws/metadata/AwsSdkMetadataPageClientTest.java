package com.logssey.secretworker.aws.metadata;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.s3.model.ListBucketsRequest;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.ListSecretsRequest;
import software.amazon.awssdk.services.secretsmanager.model.ListSecretsResponse;
import software.amazon.awssdk.services.secretsmanager.model.SecretListEntry;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.DescribeParametersRequest;
import software.amazon.awssdk.services.ssm.model.DescribeParametersResponse;
import software.amazon.awssdk.services.ssm.model.ParameterMetadata;

class AwsSdkMetadataPageClientTest {
    @Test
    void invokesOnlyListingApisAndDiscardsNamesAndArns() {
        SecretsManagerClient secrets = mock(SecretsManagerClient.class);
        SsmClient ssm = mock(SsmClient.class);
        S3Client s3 = mock(S3Client.class);
        when(secrets.listSecrets(any(ListSecretsRequest.class))).thenReturn(ListSecretsResponse.builder()
                .secretList(SecretListEntry.builder().name("sensitive-secret-name")
                        .arn("arn:aws:secretsmanager:us-east-1:111122223333:secret:sensitive").build())
                .nextToken("next-secrets").build());
        when(ssm.describeParameters(any(DescribeParametersRequest.class))).thenReturn(
                DescribeParametersResponse.builder().parameters(ParameterMetadata.builder()
                        .name("/sensitive/parameter").build()).build());
        when(s3.listBuckets(any(ListBucketsRequest.class))).thenReturn(ListBucketsResponse.builder()
                .buckets(List.of(Bucket.builder().name("sensitive-bucket-name").build()))
                .continuationToken("next-buckets").build());
        AwsSdkMetadataPageClient client = new AwsSdkMetadataPageClient(
                region -> secrets, region -> ssm, () -> s3);

        var secretPage = client.listSecrets("us-east-1", null);
        var parameterPage = client.describeParameters("us-east-1", "ssm-token");
        var bucketPage = client.listBuckets(null);

        assertEquals(1, secretPage.itemCount());
        assertEquals("next-secrets", secretPage.nextToken());
        assertEquals(1, parameterPage.itemCount());
        assertEquals(1, bucketPage.itemCount());
        assertFalse(secretPage.toString().contains("sensitive-secret-name"));
        assertFalse(parameterPage.toString().contains("/sensitive/parameter"));
        assertFalse(bucketPage.toString().contains("sensitive-bucket-name"));
        var secretRequest = org.mockito.ArgumentCaptor.forClass(ListSecretsRequest.class);
        var ssmRequest = org.mockito.ArgumentCaptor.forClass(DescribeParametersRequest.class);
        var bucketRequest = org.mockito.ArgumentCaptor.forClass(ListBucketsRequest.class);
        verify(secrets).listSecrets(secretRequest.capture());
        verify(ssm).describeParameters(ssmRequest.capture());
        verify(s3).listBuckets(bucketRequest.capture());
        assertEquals(100, secretRequest.getValue().maxResults());
        assertEquals("ssm-token", ssmRequest.getValue().nextToken());
        assertEquals(50, ssmRequest.getValue().maxResults());
        assertEquals(1_000, bucketRequest.getValue().maxBuckets());
        verify(secrets).close();
        verify(ssm).close();
        verify(s3).close();
        verifyNoMoreInteractions(secrets, ssm, s3);
    }

    @Test
    void providerErrorBodyIsReplacedByFixedCode() {
        SecretsManagerClient secrets = mock(SecretsManagerClient.class);
        when(secrets.listSecrets(any(ListSecretsRequest.class))).thenThrow(SecretsManagerException.builder()
                .statusCode(403).message("sensitive-resource-name").build());
        AwsSdkMetadataPageClient client = new AwsSdkMetadataPageClient(
                region -> secrets, region -> mock(SsmClient.class), () -> mock(S3Client.class));

        var failure = assertThrows(AwsMetadataPageClient.Failure.class,
                () -> client.listSecrets("us-east-1", null));
        assertEquals(AwsMetadataCollector.GapCode.ACCESS_DENIED, failure.code());
        assertFalse(failure.getMessage().contains("sensitive-resource-name"));
        assertEquals(null, failure.getCause());
    }
}
