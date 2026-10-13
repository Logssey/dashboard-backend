package com.logssey.secretworker.aws.content;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.GetParameterRequest;

import static com.logssey.secretworker.aws.content.AwsContentReader.FailureCode;
import static com.logssey.secretworker.aws.content.AwsContentReader.ReadFailure;

/** Provider adapter. It never logs request, response, or provider exception text. */
public final class AwsSdkContentReader implements AwsContentReader {
    interface ClientFactory {
        SecretsManagerClient secretsManager(String region);
        SsmClient ssm(String region);
        S3Client s3(String region);
    }

    private final ClientFactory clients;

    public AwsSdkContentReader(AwsCredentialsProvider credentials) {
        Objects.requireNonNull(credentials);
        this.clients = new ClientFactory() {
            @Override public SecretsManagerClient secretsManager(String region) {
                return SecretsManagerClient.builder().credentialsProvider(credentials)
                        .region(Region.of(region)).build();
            }
            @Override public SsmClient ssm(String region) {
                return SsmClient.builder().credentialsProvider(credentials)
                        .region(Region.of(region)).build();
            }
            @Override public S3Client s3(String region) {
                return S3Client.builder().credentialsProvider(credentials)
                        .region(Region.of(region)).build();
            }
        };
    }

    AwsSdkContentReader(ClientFactory clients) {
        this.clients = Objects.requireNonNull(clients);
    }

    @Override public byte[] read(AwsContentScope scope, int maxBytes) {
        Objects.requireNonNull(scope);
        if (maxBytes < 1 || maxBytes > AwsContentCollector.ABSOLUTE_MAX_BYTES) {
            throw new IllegalArgumentException("Invalid AWS content byte limit");
        }
        try {
            return switch (scope.kind()) {
                case SECRETS_MANAGER -> readSecret(scope, maxBytes);
                case SSM_PARAMETER -> readParameter(scope, maxBytes);
                case S3_OBJECT -> readObject(scope, maxBytes);
            };
        } catch (ReadFailure error) {
            throw error;
        } catch (AwsServiceException error) {
            throw new ReadFailure(serviceCode(error.statusCode()));
        } catch (SdkClientException error) {
            throw new ReadFailure(FailureCode.UNAVAILABLE);
        } catch (IOException error) {
            throw new ReadFailure(FailureCode.UNAVAILABLE);
        }
    }

    private byte[] readSecret(AwsContentScope scope, int maxBytes) {
        try (var client = clients.secretsManager(scope.region())) {
            var response = client.getSecretValue(GetSecretValueRequest.builder()
                    .secretId(scope.resource()).versionStage("AWSCURRENT").build());
            if (response.secretString() == null) throw new ReadFailure(FailureCode.NON_TEXT);
            return utf8Bounded(response.secretString(), maxBytes);
        }
    }

    private byte[] readParameter(AwsContentScope scope, int maxBytes) {
        try (var client = clients.ssm(scope.region())) {
            var response = client.getParameter(GetParameterRequest.builder()
                    .name(scope.resource()).withDecryption(true).build());
            if (response.parameter() == null || response.parameter().value() == null) {
                throw new ReadFailure(FailureCode.UNAVAILABLE);
            }
            return utf8Bounded(response.parameter().value(), maxBytes);
        }
    }

    private byte[] readObject(AwsContentScope scope, int maxBytes) throws IOException {
        try (var client = clients.s3(scope.region())) {
            var head = client.headObject(HeadObjectRequest.builder().bucket(scope.resource())
                    .key(scope.objectKey()).expectedBucketOwner(scope.accountId()).build());
            if (head.contentLength() == null || head.contentLength() < 0) {
                throw new ReadFailure(FailureCode.UNAVAILABLE);
            }
            if (head.contentLength() > maxBytes) throw new ReadFailure(FailureCode.TOO_LARGE);
            if (head.eTag() == null || head.eTag().isBlank()) {
                throw new ReadFailure(FailureCode.UNAVAILABLE);
            }
            GetObjectRequest.Builder request = GetObjectRequest.builder().bucket(scope.resource())
                    .key(scope.objectKey()).expectedBucketOwner(scope.accountId()).ifMatch(head.eTag());
            if (head.versionId() != null && !head.versionId().isBlank()) {
                request.versionId(head.versionId());
            }
            try (ResponseInputStream<GetObjectResponse> stream = client.getObject(request.build())) {
                byte[] content = stream.readNBytes(maxBytes + 1);
                if (content.length > maxBytes) {
                    Arrays.fill(content, (byte) 0);
                    throw new ReadFailure(FailureCode.TOO_LARGE);
                }
                if (content.length != head.contentLength()) {
                    Arrays.fill(content, (byte) 0);
                    throw new ReadFailure(FailureCode.UNAVAILABLE);
                }
                return content;
            }
        }
    }

    private static byte[] utf8Bounded(String value, int maxBytes) {
        // AWS SDK has already materialized SecretString/value as an immutable String.
        // The returned byte[] is short-lived and zeroed by AwsContentCollector.
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > maxBytes) {
            Arrays.fill(bytes, (byte) 0);
            throw new ReadFailure(FailureCode.TOO_LARGE);
        }
        return bytes;
    }

    private static FailureCode serviceCode(int status) {
        return switch (status) {
            case 401, 403 -> FailureCode.ACCESS_DENIED;
            case 404 -> FailureCode.NOT_FOUND;
            case 429, 503 -> FailureCode.RATE_LIMITED;
            default -> FailureCode.UNAVAILABLE;
        };
    }
}
