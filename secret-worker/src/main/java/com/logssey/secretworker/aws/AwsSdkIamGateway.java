package com.logssey.secretworker.aws;

import com.logssey.secret.run.progress.core.ScanExecutionObserver;
import com.logssey.secret.run.progress.core.ScanExecutionObserver.Operation;
import com.logssey.secretworker.progress.AwsScanObservation;
import java.util.List;
import java.util.Objects;

import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
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
    private ScanExecutionObserver observer = ScanExecutionObserver.NONE;
    private final StsClient sts;
    private final IamClient iam;
    private final ProfileCredentialsProvider ownedCredentials;

    public AwsSdkIamGateway(String profile) {
        this(ProfileCredentialsProvider.create(validProfile(profile)), true);
    }

    /** The caller owns a supplied provider, so IAM and other AWS clients may share it. */
    public AwsSdkIamGateway(AwsCredentialsProvider credentials) {
        this(credentials, false);
    }

    private AwsSdkIamGateway(AwsCredentialsProvider credentials, boolean ownsProvider) {
        Objects.requireNonNull(credentials);
        ownedCredentials = ownsProvider ? (ProfileCredentialsProvider) credentials : null;
        // SDK clients close closeable providers; only the owner may close this shared profile.
        AwsCredentialsProvider borrowed = credentials::resolveCredentials;
        sts = StsClient.builder().credentialsProvider(borrowed).region(Region.US_EAST_1).build();
        iam = IamClient.builder().credentialsProvider(borrowed).region(Region.AWS_GLOBAL).build();
    }

    private static String validProfile(String profile) {
        if (profile == null || !profile.matches("[A-Za-z0-9._-]{1,100}")) {
            throw new IllegalArgumentException("AWS_PROFILE_REQUIRED");
        }
        return profile;
    }

    AwsSdkIamGateway(StsClient sts, IamClient iam) {
        this.sts = sts;
        this.iam = iam;
        this.ownedCredentials = null;
    }

    @Override
    public AwsIamGateway observed(ScanExecutionObserver observer) {
        var copy = new AwsSdkIamGateway(sts, iam);
        copy.observer = Objects.requireNonNull(observer);
        return copy;
    }

    @Override
    public String accountId() {
        try {
            return AwsScanObservation.call(observer, Operation.AWS_GET_CALLER_IDENTITY, () -> sts.getCallerIdentity(GetCallerIdentityRequest.builder().build())).account();
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
            var response = AwsScanObservation.call(observer, Operation.AWS_LIST_USERS, () -> iam.listUsers(request.build()));
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
            var response = AwsScanObservation.call(observer, Operation.AWS_LIST_ACCESS_KEYS, () -> iam.listAccessKeys(request.build()));
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
            var response = AwsScanObservation.call(observer, Operation.AWS_GET_ACCESS_KEY_LAST_USED, () -> iam.getAccessKeyLastUsed(GetAccessKeyLastUsedRequest.builder()
                    .accessKeyId(accessKeyId).build()));
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
            var response = AwsScanObservation.call(observer, Operation.AWS_GET_ACCOUNT_SUMMARY, () -> iam.getAccountSummary(GetAccountSummaryRequest.builder().build()));
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
        if (ownedCredentials != null) ownedCredentials.close();
    }
}
