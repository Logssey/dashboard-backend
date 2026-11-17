package com.logssey.complianceworker;

import static com.logssey.complianceworker.WorkerDtos.AwsCallerIdentity;
import static com.logssey.complianceworker.WorkerDtos.ClaimedJob;

import java.time.Duration;
import java.net.URI;

import org.springframework.stereotype.Service;

import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.StsException;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;

/** Worker workload identity로 등록된 대상 역할을 맡아 실제 계정 ID를 확인한다. */
@Service
public class AwsTargetIdentityService {

    private final ComplianceWorkerProperties properties;

    public AwsTargetIdentityService(ComplianceWorkerProperties properties) {
        this.properties = properties;
    }

    AwsCallerIdentity verify(ClaimedJob job) {
        if (job.target() == null || job.target().roleArn() == null || job.target().externalId() == null) {
            throw new TargetIdentityException("TARGET_CONFIGURATION_INVALID", false);
        }
        Region region = Region.of(properties.awsRegion());
        var baseBuilder = StsClient.builder()
                .region(region)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .httpClientBuilder(UrlConnectionHttpClient.builder().connectionTimeout(Duration.ofSeconds(10)));
        if (properties.stsEndpoint() != null && !properties.stsEndpoint().isBlank()) {
            baseBuilder.endpointOverride(URI.create(properties.stsEndpoint()));
        }
        try (var base = baseBuilder.build()) {
            var assumed = base.assumeRole(AssumeRoleRequest.builder()
                    .roleArn(job.target().roleArn())
                    .externalId(job.target().externalId())
                    .roleSessionName("logssey-" + job.jobId())
                    .durationSeconds(900)
                    .build());
            var credentials = assumed.credentials();
            var temporary = AwsSessionCredentials.create(credentials.accessKeyId(), credentials.secretAccessKey(),
                    credentials.sessionToken());
            var targetBuilder = StsClient.builder()
                    .region(region)
                    .credentialsProvider(StaticCredentialsProvider.create(temporary))
                    .httpClientBuilder(UrlConnectionHttpClient.builder().connectionTimeout(Duration.ofSeconds(10)));
            if (properties.stsEndpoint() != null && !properties.stsEndpoint().isBlank()) {
                targetBuilder.endpointOverride(URI.create(properties.stsEndpoint()));
            }
            try (var target = targetBuilder.build()) {
                var identity = target.getCallerIdentity();
                return new AwsCallerIdentity(identity.account(), identity.arn());
            }
        } catch (StsException e) {
            String code = e.awsErrorDetails() == null ? null : e.awsErrorDetails().errorCode();
            boolean retryable = e.isThrottlingException() || e.statusCode() >= 500;
            throw new TargetIdentityException("AccessDenied".equals(code)
                    ? "TARGET_ASSUME_ROLE_DENIED" : "TARGET_STS_FAILURE", retryable);
        } catch (SdkClientException e) {
            throw new TargetIdentityException("WORKER_IDENTITY_UNAVAILABLE", true);
        }
    }

    static final class TargetIdentityException extends RuntimeException {
        private final String code;
        private final boolean retryable;

        TargetIdentityException(String code, boolean retryable) {
            super(code);
            this.code = code;
            this.retryable = retryable;
        }

        String code() { return code; }
        boolean retryable() { return retryable; }
    }
}
