package com.logssey.secret.connection;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class SecretConnectionTestServiceTest {
    private final SecretConnectionTestRepository repository = mock(SecretConnectionTestRepository.class);
    private final AwsIdentityProbe aws = mock(AwsIdentityProbe.class);
    private final GitHubAuthProbe github = mock(GitHubAuthProbe.class);
    private final SecretConnectionTestService service = new SecretConnectionTestService(
            repository, aws, github, Clock.fixed(Instant.parse("2026-10-14T01:02:03Z"), ZoneOffset.UTC));

    @Test
    void adminProbesAwsIdentityWithoutReturningAccountOrProfile() {
        when(repository.actorRole("admin")).thenReturn(Optional.of("ADMIN"));
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
    void rejectsNonAdminAndPausedBeforeProbing() {
        when(repository.actorRole("user")).thenReturn(Optional.of("USER"));
        assertThatThrownBy(() -> service.test(7, "user"))
                .isInstanceOfSatisfying(ApiException.class,
                        error -> assertThat(error.errorCode()).isEqualTo(ErrorCode.FORBIDDEN));
        when(repository.actorRole("admin")).thenReturn(Optional.of("ADMIN"));
        when(repository.connection(7)).thenReturn(Optional.of(new SecretConnectionTestRepository.Connection(
                7, "AWS", "PAUSED", "aws-profile:test")));
        assertThatThrownBy(() -> service.test(7, "admin"))
                .isInstanceOfSatisfying(ApiException.class,
                        error -> assertThat(error.errorCode()).isEqualTo(ErrorCode.CONFLICT));
        verifyNoInteractions(aws, github);
    }

    @Test
    void malformedOrMixedAwsScopesNeverReachSts() {
        when(repository.actorRole("admin")).thenReturn(Optional.of("ADMIN"));
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
        when(repository.actorRole("admin")).thenReturn(Optional.of("ADMIN"));
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
