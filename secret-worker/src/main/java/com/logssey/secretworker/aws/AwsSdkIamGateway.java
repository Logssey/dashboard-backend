package com.logssey.secretworker.aws;

import java.util.List;

import software.amazon.awssdk.auth.credentials.ProfileCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.GetAccessKeyLastUsedRequest;
import software.amazon.awssdk.services.iam.model.GetAccountSummaryRequest;
import software.amazon.awssdk.services.iam.model.ListAccessKeysRequest;
import software.amazon.awssdk.services.iam.model.ListUsersRequest;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;
import software.amazon.awssdk.awscore.exception.AwsServiceException;

/** Deliberately exposes only read-only IAM and STS operations. */
public final class AwsSdkIamGateway implements AwsIamGateway {
    private final StsClient sts;
    private final IamClient iam;
    private final ProfileCredentialsProvider credentials;

    public AwsSdkIamGateway(String profile) {
        if (profile == null || !profile.matches("[A-Za-z0-9._-]{1,100}")) {
            throw new IllegalArgumentException("AWS_PROFILE_REQUIRED");
        }
        credentials = ProfileCredentialsProvider.create(profile);
        sts = StsClient.builder().credentialsProvider(credentials).region(Region.US_EAST_1).build();
        iam = IamClient.builder().credentialsProvider(credentials).region(Region.AWS_GLOBAL).build();
    }

    AwsSdkIamGateway(StsClient sts, IamClient iam) {
        this.sts = sts;
        this.iam = iam;
        this.credentials = null;
    }

    @Override
    public String accountId() {
        try {
            return sts.getCallerIdentity(GetCallerIdentityRequest.builder().build()).account();
        } catch (AwsServiceException error) {
            throw safe(error);
        } catch (SdkClientException error) {
            throw new AwsIamSourceException(AwsIamSourceException.Code.UNAVAILABLE);
        }
    }

    @Override
    public Page<String> users(String marker) {
        try {
            var request = ListUsersRequest.builder().maxItems(100);
            if (marker != null) request.marker(marker);
            var response = iam.listUsers(request.build());
            List<String> names = response.users().stream().map(user -> user.userName()).toList();
            return new Page<>(names, next(response.isTruncated(), response.marker()));
        } catch (AwsServiceException error) {
            throw safe(error);
        } catch (SdkClientException error) {
            throw new AwsIamSourceException(AwsIamSourceException.Code.UNAVAILABLE);
        }
    }

    @Override
    public Page<AccessKey> accessKeys(String userName, String marker) {
        try {
            var request = ListAccessKeysRequest.builder().userName(userName).maxItems(100);
            if (marker != null) request.marker(marker);
            var response = iam.listAccessKeys(request.build());
            List<AccessKey> keys = response.accessKeyMetadata().stream()
                    .map(key -> new AccessKey(key.accessKeyId(), key.userName(),
                            key.statusAsString(), key.createDate())).toList();
            return new Page<>(keys, next(response.isTruncated(), response.marker()));
        } catch (AwsServiceException error) {
            throw safe(error);
        } catch (SdkClientException error) {
            throw new AwsIamSourceException(AwsIamSourceException.Code.UNAVAILABLE);
        }
    }

    @Override
    public LastUsed lastUsed(String accessKeyId) {
        try {
            var response = iam.getAccessKeyLastUsed(GetAccessKeyLastUsedRequest.builder()
                    .accessKeyId(accessKeyId).build());
            var usage = response.accessKeyLastUsed();
            if (usage == null) return new LastUsed(null, null, null);
            return new LastUsed(usage.lastUsedDate(), usage.serviceName(), usage.region());
        } catch (AwsServiceException error) {
            throw safe(error);
        } catch (SdkClientException error) {
            throw new AwsIamSourceException(AwsIamSourceException.Code.UNAVAILABLE);
        }
    }

    @Override
    public int rootAccessKeyCount() {
        try {
            var response = iam.getAccountSummary(GetAccountSummaryRequest.builder().build());
            Integer count = response.summaryMapAsStrings().get("AccountAccessKeysPresent");
            if (count == null || count < 0) {
                throw new AwsIamSourceException(AwsIamSourceException.Code.INVALID_RESPONSE);
            }
            return count;
        } catch (AwsServiceException error) {
            throw safe(error);
        } catch (SdkClientException error) {
            throw new AwsIamSourceException(AwsIamSourceException.Code.UNAVAILABLE);
        }
    }

    private static String next(Boolean truncated, String marker) {
        if (!Boolean.TRUE.equals(truncated)) return null;
        if (marker == null || marker.isBlank()) {
            throw new AwsIamSourceException(AwsIamSourceException.Code.INVALID_RESPONSE);
        }
        return marker;
    }

    private static AwsIamSourceException safe(AwsServiceException error) {
        int status = error.statusCode();
        if (status == 401 || status == 403) {
            return new AwsIamSourceException(AwsIamSourceException.Code.ACCESS_DENIED);
        }
        if (status == 429 || status == 503) {
            return new AwsIamSourceException(AwsIamSourceException.Code.RATE_LIMITED);
        }
        return new AwsIamSourceException(AwsIamSourceException.Code.UNAVAILABLE);
    }

    @Override
    public void close() {
        iam.close();
        sts.close();
        if (credentials != null) credentials.close();
    }
}
