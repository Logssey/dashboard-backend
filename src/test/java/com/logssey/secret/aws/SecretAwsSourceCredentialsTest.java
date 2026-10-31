package com.logssey.secret.aws;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.core.SdkSystemSetting;
import software.amazon.awssdk.utils.SdkAutoCloseable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class SecretAwsSourceCredentialsTest {
    @Test void explicitProfileIsPreservedAndInvalidModesCannotChooseAnotherIdentity() {
        try (var credentials = SecretAwsSourceCredentials.fromConfiguration("PROFILE", "named-source")) {
            assertThat(credentials.authRef()).isEqualTo("aws-profile:named-source");
        }
        assertThatThrownBy(() -> SecretAwsSourceCredentials.fromConfiguration("PROFILE", ""))
                .hasMessage("AWS_PROFILE_REQUIRED");
        assertThatThrownBy(() -> SecretAwsSourceCredentials.fromConfiguration("DEFAULT", ""))
                .hasMessage("AWS_CREDENTIALS_MODE_INVALID");
        assertThatThrownBy(() -> SecretAwsSourceCredentials.fromConfiguration(null, "named-source"))
                .hasMessage("AWS_CREDENTIALS_MODE_INVALID");
    }

    @Test void workloadModeRequiresExplicitChoiceAndRejectsLeftoverProfile() {
        assertThatThrownBy(() -> SecretAwsSourceCredentials.fromConfiguration("WORKLOAD", "personal"))
                .hasMessage("AWS_WORKLOAD_PROFILE_FORBIDDEN");
        try (var credentials = SecretAwsSourceCredentials.fromConfiguration("WORKLOAD", "")) {
            assertThat(credentials.authRef()).isEqualTo("aws-workload:default");
        }
        assertThat(SecretAwsSourceCredentials.isReference("aws-workload:default")).isTrue();
        assertThat(SecretAwsSourceCredentials.isReference("aws-workload:other")).isFalse();
        assertThat(SecretAwsSourceCredentials.isReference("aws-profile:../../default")).isFalse();
        assertThat(SecretAwsSourceCredentials.isReference(null)).isFalse();
    }

    @Test void sourceFailurePropagatesWithoutStaticOrPersonalFallbackAndOwnerClosesProvider() {
        var delegate = mock(CloseableProvider.class);
        when(delegate.resolveCredentials()).thenThrow(SdkClientException.create("unavailable"));
        try (var credentials = new SecretAwsSourceCredentials("aws-profile:source", delegate)) {
            assertThatThrownBy(credentials::resolveCredentials).isInstanceOf(SdkClientException.class);
        }
        verify(delegate).resolveCredentials();
        verify(delegate).close();
        verifyNoMoreInteractions(delegate);
    }

    @Test void explicitWorkloadConfigurationSelectsOnlyOneIdentityEvenWhenIncomplete() {
        var configured = java.util.EnumSet.of(SdkSystemSetting.AWS_ROLE_ARN,
                SdkSystemSetting.AWS_CONTAINER_CREDENTIALS_RELATIVE_URI);
        assertThat(SecretAwsSourceCredentials.workloadKind(configured::contains))
                .isEqualTo(SecretAwsSourceCredentials.WorkloadKind.WEB_IDENTITY);
        // A token file without role ARN is still explicit IRSA, never instance fallback.
        assertThat(SecretAwsSourceCredentials.workloadKind(s -> s == SdkSystemSetting.AWS_WEB_IDENTITY_TOKEN_FILE))
                .isEqualTo(SecretAwsSourceCredentials.WorkloadKind.WEB_IDENTITY);
        // Container auth without URI is invalid container configuration, not an EC2 identity.
        assertThat(SecretAwsSourceCredentials.workloadKind(s -> s == SdkSystemSetting.AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE))
                .isEqualTo(SecretAwsSourceCredentials.WorkloadKind.CONTAINER);
        assertThat(SecretAwsSourceCredentials.workloadKind(s -> false))
                .isEqualTo(SecretAwsSourceCredentials.WorkloadKind.INSTANCE);
        // Static keys and profiles cannot influence the workload selector.
        assertThat(SecretAwsSourceCredentials.workloadKind(s -> s == SdkSystemSetting.AWS_ACCESS_KEY_ID
                || s == SdkSystemSetting.AWS_SECRET_ACCESS_KEY))
                .isEqualTo(SecretAwsSourceCredentials.WorkloadKind.INSTANCE);
    }

    @Test void sourceProviderReturnsTemporaryOrStaticIdentityUnmodifiedToOwnedClients() {
        var identity = AwsBasicCredentials.create("synthetic-id", "synthetic-secret");
        try (var credentials = new SecretAwsSourceCredentials("aws-profile:source", () -> identity)) {
            assertThat(credentials.resolveCredentials()).isSameAs(identity);
        }
    }

    private interface CloseableProvider extends AwsCredentialsProvider, SdkAutoCloseable {}
}
