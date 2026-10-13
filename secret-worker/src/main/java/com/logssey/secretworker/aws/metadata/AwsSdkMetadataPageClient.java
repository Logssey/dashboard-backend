package com.logssey.secretworker.aws.metadata;

import java.time.Duration;
import java.util.Objects;
import java.util.function.Function;
import java.util.function.Supplier;

import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.ListBucketsRequest;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.ListSecretsRequest;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.DescribeParametersRequest;

/** SDK implementation restricted to three metadata listing calls. No value or object API is reachable here. */
public final class AwsSdkMetadataPageClient implements AwsMetadataPageClient {
    private static final Duration CALL_TIMEOUT = Duration.ofSeconds(10);
    private final Function<String, SecretsManagerClient> secretsClient;
    private final Function<String, SsmClient> ssmClient;
    private final Supplier<S3Client> s3Client;

    public AwsSdkMetadataPageClient(AwsCredentialsProvider credentials) {
        Objects.requireNonNull(credentials);
        this.secretsClient = region -> SecretsManagerClient.builder()
                .region(Region.of(region)).credentialsProvider(credentials)
                .overrideConfiguration(config -> config.apiCallTimeout(CALL_TIMEOUT)).build();
        this.ssmClient = region -> SsmClient.builder()
                .region(Region.of(region)).credentialsProvider(credentials)
                .overrideConfiguration(config -> config.apiCallTimeout(CALL_TIMEOUT)).build();
        this.s3Client = () -> S3Client.builder()
                .region(Region.US_EAST_1).credentialsProvider(credentials)
                .overrideConfiguration(config -> config.apiCallTimeout(CALL_TIMEOUT)).build();
    }

    /** Allows tests to inject SDK clients without credentials or network access. */
    AwsSdkMetadataPageClient(Function<String, SecretsManagerClient> secretsClient,
                             Function<String, SsmClient> ssmClient,
                             Supplier<S3Client> s3Client) {
        this.secretsClient = Objects.requireNonNull(secretsClient);
        this.ssmClient = Objects.requireNonNull(ssmClient);
        this.s3Client = Objects.requireNonNull(s3Client);
    }

    @Override
    public Page listSecrets(String region, String nextToken) {
        try (SecretsManagerClient client = secretsClient.apply(region)) {
            ListSecretsRequest.Builder request = ListSecretsRequest.builder().maxResults(100);
            if (nextToken != null) request.nextToken(nextToken);
            var response = client.listSecrets(request.build());
            return new Page(response.secretList().size(), response.nextToken());
        } catch (AwsServiceException error) {
            throw new Failure(map(error));
        } catch (SdkClientException error) {
            throw new Failure(AwsMetadataCollector.GapCode.SOURCE_UNAVAILABLE);
        } catch (RuntimeException error) {
            throw new Failure(AwsMetadataCollector.GapCode.API_ERROR);
        }
    }

    @Override
    public Page describeParameters(String region, String nextToken) {
        try (SsmClient client = ssmClient.apply(region)) {
            DescribeParametersRequest.Builder request = DescribeParametersRequest.builder().maxResults(50);
            if (nextToken != null) request.nextToken(nextToken);
            var response = client.describeParameters(request.build());
            return new Page(response.parameters().size(), response.nextToken());
        } catch (AwsServiceException error) {
            throw new Failure(map(error));
        } catch (SdkClientException error) {
            throw new Failure(AwsMetadataCollector.GapCode.SOURCE_UNAVAILABLE);
        } catch (RuntimeException error) {
            throw new Failure(AwsMetadataCollector.GapCode.API_ERROR);
        }
    }

    @Override
    public Page listBuckets(String nextToken) {
        try (S3Client client = s3Client.get()) {
            ListBucketsRequest.Builder request = ListBucketsRequest.builder().maxBuckets(1_000);
            if (nextToken != null) request.continuationToken(nextToken);
            var response = client.listBuckets(request.build());
            return new Page(response.buckets().size(), response.continuationToken());
        } catch (AwsServiceException error) {
            throw new Failure(map(error));
        } catch (SdkClientException error) {
            throw new Failure(AwsMetadataCollector.GapCode.SOURCE_UNAVAILABLE);
        } catch (RuntimeException error) {
            throw new Failure(AwsMetadataCollector.GapCode.API_ERROR);
        }
    }

    private static AwsMetadataCollector.GapCode map(AwsServiceException error) {
        int status = error.statusCode();
        String code = error.awsErrorDetails() == null ? null : error.awsErrorDetails().errorCode();
        if (status == 401 || status == 403 || "AccessDeniedException".equals(code)
                || "AccessDenied".equals(code) || "UnauthorizedOperation".equals(code)) {
            return AwsMetadataCollector.GapCode.ACCESS_DENIED;
        }
        if (status == 429 || "ThrottlingException".equals(code) || "Throttling".equals(code)
                || "TooManyRequestsException".equals(code) || "RequestLimitExceeded".equals(code)) {
            return AwsMetadataCollector.GapCode.RATE_LIMITED;
        }
        if (status >= 500) return AwsMetadataCollector.GapCode.SOURCE_UNAVAILABLE;
        return AwsMetadataCollector.GapCode.API_ERROR;
    }
}
