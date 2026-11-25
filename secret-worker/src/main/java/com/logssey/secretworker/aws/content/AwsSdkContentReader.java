package com.logssey.secretworker.aws.content;

import com.logssey.secret.run.progress.core.ScanExecutionObserver;
import com.logssey.secret.run.progress.core.ScanExecutionObserver.Operation;
import com.logssey.secretworker.progress.AwsScanObservation;
import static com.logssey.secret.run.progress.core.ScanExecutionObserver.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

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
    private static final Duration API_TIMEOUT = Duration.ofSeconds(30);
    interface ClientFactory {
        SecretsManagerClient secretsManager(String region);
        SsmClient ssm(String region);
        S3Client s3(String region);
    }

    private ScanExecutionObserver observer = ScanExecutionObserver.NONE;
    private final ClientFactory clients;

    public AwsSdkContentReader(AwsCredentialsProvider credentials) {
        Objects.requireNonNull(credentials);
        // Each value client is short-lived; closing it must not close the shared provider.
        AwsCredentialsProvider borrowed = credentials::resolveCredentials;
        this.clients = new ClientFactory() {
            @Override public SecretsManagerClient secretsManager(String region) {
                return SecretsManagerClient.builder().credentialsProvider(borrowed)
                        .region(Region.of(region))
                        .overrideConfiguration(config -> config.apiCallTimeout(API_TIMEOUT)).build();
            }
            @Override public SsmClient ssm(String region) {
                return SsmClient.builder().credentialsProvider(borrowed)
                        .region(Region.of(region))
                        .overrideConfiguration(config -> config.apiCallTimeout(API_TIMEOUT)).build();
            }
            @Override public S3Client s3(String region) {
                return S3Client.builder().credentialsProvider(borrowed)
                        .region(Region.of(region))
                        .overrideConfiguration(config -> config.apiCallTimeout(API_TIMEOUT)).build();
            }
        };
    }

    AwsSdkContentReader(ClientFactory clients) {
        this.clients = Objects.requireNonNull(clients);
    }

    @Override public AwsContentReader observed(ScanExecutionObserver observer) {
        var copy = new AwsSdkContentReader(clients);
        copy.observer = Objects.requireNonNull(observer);
        return copy;
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
                case S3_PREFIX -> throw new IllegalArgumentException("List a prefix before reading objects");
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

    @Override public ObjectPage list(AwsContentScope scope, String token) {
        if (scope.kind() != AwsContentScope.Kind.S3_PREFIX) throw new IllegalArgumentException("Prefix required");
        try (var client = clients.s3(scope.region())) {
            var request = software.amazon.awssdk.services.s3.model.ListObjectsV2Request.builder()
                    .bucket(scope.resource()).prefix(scope.objectKey()).expectedBucketOwner(scope.accountId())
                    .maxKeys(1000).continuationToken(token).build();
            var response = AwsScanObservation.call(observer, Operation.SCOPE_COLLECTION,
                    () -> client.listObjectsV2(request));
            String next = Boolean.TRUE.equals(response.isTruncated()) ? response.nextContinuationToken() : null;
            if (Boolean.TRUE.equals(response.isTruncated()) && (next == null || next.isBlank()))
                throw new ReadFailure(FailureCode.UNAVAILABLE);
            return new ObjectPage(response.contents().stream().map(o -> o.key()).toList(), next);
        } catch (AwsServiceException error) {
            throw new ReadFailure(serviceCode(error.statusCode()));
        } catch (SdkClientException error) {
            throw new ReadFailure(FailureCode.UNAVAILABLE);
        }
    }

    private byte[] readSecret(AwsContentScope scope, int maxBytes) {
        byte[] content = null;
        try (var client = clients.secretsManager(scope.region())) {
            var response = AwsScanObservation.call(observer, Operation.AWS_GET_SECRET_VALUE, () -> client.getSecretValue(GetSecretValueRequest.builder()
                    .secretId(scope.resource()).versionStage("AWSCURRENT").build()));
            if (response.secretString() == null) throw new ReadFailure(FailureCode.NON_TEXT);
            content = utf8Bounded(response.secretString(), maxBytes);
        } catch (RuntimeException error) {
            if (content != null) Arrays.fill(content, (byte) 0);
            throw error;
        }
        return content;
    }

    private byte[] readParameter(AwsContentScope scope, int maxBytes) {
        byte[] content = null;
        try (var client = clients.ssm(scope.region())) {
            var response = AwsScanObservation.call(observer, Operation.AWS_GET_PARAMETER, () -> client.getParameter(GetParameterRequest.builder()
                    .name(scope.resource()).withDecryption(true).build()));
            if (response.parameter() == null || response.parameter().value() == null) {
                throw new ReadFailure(FailureCode.UNAVAILABLE);
            }
            content = utf8Bounded(response.parameter().value(), maxBytes);
        } catch (RuntimeException error) {
            if (content != null) Arrays.fill(content, (byte) 0);
            throw error;
        }
        return content;
    }

    private byte[] readObject(AwsContentScope scope, int maxBytes) throws IOException {
        byte[] content = null;
        try (var client = clients.s3(scope.region())) {
            var head = AwsScanObservation.call(observer, Operation.AWS_HEAD_OBJECT, () -> client.headObject(HeadObjectRequest.builder().bucket(scope.resource())
                    .key(scope.objectKey()).expectedBucketOwner(scope.accountId()).build()));
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
            try (ResponseInputStream<GetObjectResponse> stream = getObject(client, request.build());
                 var watchdog = Executors.newSingleThreadScheduledExecutor(
                         Thread.ofVirtual().name("aws-s3-value-watchdog").factory())) {
                // Bound body consumption as well as the SDK request. abort() closes a stalled stream.
                var timeout = watchdog.schedule(stream::abort, API_TIMEOUT.toMillis(),
                        TimeUnit.MILLISECONDS);
                try {
                    content = stream.readNBytes(maxBytes + 1);
                    if (content.length > maxBytes) {
                        throw new ReadFailure(FailureCode.TOO_LARGE);
                    }
                    if (content.length != head.contentLength()) {
                        throw new ReadFailure(FailureCode.UNAVAILABLE);
                    }
                } finally {
                    timeout.cancel(false);
                }
            }
        } catch (IOException | RuntimeException error) {
            if (content != null) Arrays.fill(content, (byte) 0);
            throw error;
        }
        return content;
    }

    private ResponseInputStream<GetObjectResponse> getObject(S3Client client, GetObjectRequest request) {
        observer.record(Stage.COLLECTION, Operation.AWS_GET_OBJECT, Outcome.STARTED, null, null, null, null, null);
        long started = System.nanoTime();
        try {
            var response = client.getObject(request);
            Integer status = response.response().sdkHttpResponse() == null ? null
                    : AwsScanObservation.validStatus(response.response().sdkHttpResponse().statusCode());
            try {
                observer.record(Stage.COLLECTION, Operation.AWS_GET_OBJECT, Outcome.COMPLETED, status,
                        null, null, null, ScanExecutionObserver.elapsed(started));
            } catch (RuntimeException failure) {
                response.abort();
                throw failure;
            }
            return response;
        } catch (AwsServiceException failure) {
            observer.record(Stage.COLLECTION, Operation.AWS_GET_OBJECT, Outcome.FAILED,
                    AwsScanObservation.validStatus(failure.statusCode()), "OPERATION_FAILED", null, null,
                    ScanExecutionObserver.elapsed(started));
            throw failure;
        } catch (SdkClientException failure) {
            observer.record(Stage.COLLECTION, Operation.AWS_GET_OBJECT, Outcome.FAILED,
                    null, "NETWORK_ERROR", null, null, ScanExecutionObserver.elapsed(started));
            throw failure;
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
