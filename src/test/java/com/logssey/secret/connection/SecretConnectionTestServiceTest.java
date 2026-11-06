package com.logssey.secret.connection;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.access.SecretPrincipal;
import com.logssey.secret.access.SecretRole;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class SecretConnectionTestServiceTest {
    @Test
    void notionProbeUsesOnlyTheConfiguredConnectionAndRequiresEveryApprovedScopeToBeSupported() {
        var repository=mock(SecretConnectionTestRepository.class);
        var access=mock(SecretAccessService.class);
        var aws=mock(AwsIdentityProbe.class);var github=mock(GitHubAuthProbe.class);var notion=mock(NotionAuthProbe.class);
        var service=new SecretConnectionTestService(repository,aws,github,notion,
                Clock.systemUTC(),access);
        when(access.requirePrincipal("operator")).thenReturn(new SecretPrincipal(1));
        when(repository.connection(9)).thenReturn(Optional.of(new SecretConnectionTestRepository.Connection(
                9,"NOTION","ACTIVE","notion-internal:default")));
        when(repository.notionScopesSupported(9)).thenReturn(false);
        assertThat(service.test(9,"operator").reasonCode()).isEqualTo("INVALID_APPROVED_SCOPE");
        verifyNoInteractions(notion);
        when(repository.notionScopesSupported(9)).thenReturn(true);
        when(notion.probe("notion-internal:default")).thenReturn(ConnectionProbeResult.connected());
        assertThat(service.test(9,"operator").status()).isEqualTo("CONNECTED");
        verify(notion).probe("notion-internal:default");verifyNoInteractions(aws,github);
    }

    private final SecretConnectionTestRepository repository = mock(SecretConnectionTestRepository.class);
    private final SecretAccessService access = mock(SecretAccessService.class);
    private final AwsIdentityProbe aws = mock(AwsIdentityProbe.class);
    private final GitHubAuthProbe github = mock(GitHubAuthProbe.class);
    private final SecretConnectionTestService service = new SecretConnectionTestService(
            repository, aws, github, Clock.fixed(Instant.parse("2026-10-14T01:02:03Z"), ZoneOffset.UTC), access);

    @Test
    void workloadReferenceProbesOnlyConfiguredWorkloadIdentityAndNeverAProfile() {
        when(access.requirePrincipal("admin")).thenReturn(new SecretPrincipal(1));
        when(repository.connection(7)).thenReturn(Optional.of(new SecretConnectionTestRepository.Connection(
                7, "AWS", "ACTIVE", "aws-workload:default")));
        when(repository.awsScopes(7)).thenReturn(new SecretConnectionTestRepository.AwsScopeSummary(
                1, 0, 1, "123456789012"));
        when(aws.probeWorkload("123456789012")).thenReturn(ConnectionProbeResult.connected());
        assertThat(service.test(7, "admin").status()).isEqualTo("CONNECTED");
        verify(aws).probeWorkload("123456789012");
        verify(aws, never()).probe(anyString(), anyString());
    }

    @Test
    void identityProbeRejectsWrongRuntimeModeBeforeResolvingAnyCredentials() {
        assertThat(new AwsIdentityProbe("PROFILE").probeWorkload("123456789012").reasonCode())
                .isEqualTo("AWS_UNAVAILABLE");
        assertThat(new AwsIdentityProbe("WORKLOAD").probe("personal", "123456789012").reasonCode())
                .isEqualTo("AWS_UNAVAILABLE");
    }

    @Test
    void operationsProbesAwsIdentityWithoutReturningAccountOrProfile() {
        when(access.requirePrincipal("admin")).thenReturn(new SecretPrincipal(1));
        when(repository.connection(7)).thenReturn(Optional.of(new SecretConnectionTestRepository.Connection(
                7, "AWS", "ACTIVE", "aws-profile:test")));
        when(repository.awsScopes(7)).thenReturn(new SecretConnectionTestRepository.AwsScopeSummary(
                2, 0, 1, "123456789012"));
        when(aws.probe("test", "123456789012")).thenReturn(ConnectionProbeResult.connected());

        var result = service.test(7, "admin");

        assertThat(result.connectionId()).isEqualTo(7);
        assertThat(result.provider()).isEqualTo("AWS");
        assertThat(result.status()).isEqualTo("CONNECTED");
        assertThat(result.reasonCode()).isNull();
        assertThat(result.checkedAt().toInstant()).isEqualTo(Instant.parse("2026-10-14T01:02:03Z"));
        assertThat(result.toString()).doesNotContain("123456789012", "aws-profile", "test");
        verifyNoInteractions(github);
    }

    @Test
    void rejectsMissingOperationsGrantAndPausedBeforeProbing() {
        when(access.requirePrincipal("user")).thenReturn(new SecretPrincipal(2));
        doThrow(new ApiException(ErrorCode.FORBIDDEN)).when(access)
                .requireConnectionRole(new SecretPrincipal(2), 7, SecretRole.OPERATIONS);
        assertThatThrownBy(() -> service.test(7, "user"))
                .isInstanceOfSatisfying(ApiException.class,
                        error -> assertThat(error.errorCode()).isEqualTo(ErrorCode.FORBIDDEN));
        when(access.requirePrincipal("admin")).thenReturn(new SecretPrincipal(1));
        when(repository.connection(7)).thenReturn(Optional.of(new SecretConnectionTestRepository.Connection(
                7, "AWS", "PAUSED", "aws-profile:test")));
        assertThatThrownBy(() -> service.test(7, "admin"))
                .isInstanceOfSatisfying(ApiException.class,
                        error -> assertThat(error.errorCode()).isEqualTo(ErrorCode.CONFLICT));
        verifyNoInteractions(aws, github);
    }

    @Test
    void malformedOrMixedAwsScopesNeverReachSts() {
        when(access.requirePrincipal("admin")).thenReturn(new SecretPrincipal(1));
        when(repository.connection(7)).thenReturn(Optional.of(new SecretConnectionTestRepository.Connection(
                7, "AWS", "ACTIVE", "aws-profile:test")));
        when(repository.awsScopes(7)).thenReturn(new SecretConnectionTestRepository.AwsScopeSummary(
                2, 1, 1, "123456789012"));
        assertThat(service.test(7, "admin").reasonCode()).isEqualTo("INVALID_APPROVED_SCOPE");
        when(repository.awsScopes(7)).thenReturn(new SecretConnectionTestRepository.AwsScopeSummary(
                2, 0, 2, "123456789012"));
        assertThat(service.test(7, "admin").reasonCode()).isEqualTo("INVALID_APPROVED_SCOPE");
        verifyNoInteractions(aws, github);
    }

    @Test
    void githubUsesOneEnabledApprovedScopeAndReturnsSafeFailureCode() {
        when(access.requirePrincipal("admin")).thenReturn(new SecretPrincipal(1));
        when(repository.connection(8)).thenReturn(Optional.of(new SecretConnectionTestRepository.Connection(
                8, "GITHUB", "ACTIVE", "opaque-github-app-ref")));
        var scope = new SecretConnectionTestRepository.Scope(
                "GITHUB_REPOSITORY_FILES", "github://Logssey/private-repo/develop/fixtures/",
                "CURRENT_COMMIT_ONLY");
        when(repository.firstEnabledScope(8)).thenReturn(Optional.of(scope));
        when(github.probe(scope)).thenReturn(ConnectionProbeResult.failed("GITHUB_ACCESS_DENIED"));

        var result = service.test(8, "admin");

        assertThat(result.status()).isEqualTo("FAILED");
        assertThat(result.reasonCode()).isEqualTo("GITHUB_ACCESS_DENIED");
        assertThat(result.toString()).doesNotContain("private-repo", "opaque-github-app-ref");
        verifyNoInteractions(aws);
    }
}
