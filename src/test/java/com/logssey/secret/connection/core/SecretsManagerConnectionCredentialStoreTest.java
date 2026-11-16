package com.logssey.secret.connection.core;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.Test;

import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.*;

import java.time.Instant;
import java.util.function.Consumer;

class SecretsManagerConnectionCredentialStoreTest {
    private final SecretsManagerClient client = mock(SecretsManagerClient.class);
    private final SecretsManagerConnectionCredentialStore store =
            new SecretsManagerConnectionCredentialStore(
                    client, "logssey/dashboard/source-credentials/");
    private final String name = "logssey/dashboard/source-credentials/github-controlled-reference";
    private final String version = "a".repeat(64);

    @Test
    void readsOnlyThePinnedVersionAndRejectsUncontrolledNamespace() {
        when(client.getSecretValue(any(Consumer.class)))
                .thenAnswer(
                        call -> {
                            GetSecretValueRequest.Builder request = GetSecretValueRequest.builder();
                            call.getArgument(0, Consumer.class).accept(request);
                            assertThat(request.build().secretId()).isEqualTo(name);
                            assertThat(request.build().versionId()).isEqualTo(version);
                            return GetSecretValueResponse.builder()
                                    .versionId(version)
                                    .secretString("synthetic-private-payload")
                                    .build();
                        });
        assertThat(store.get(new ConnectionCredentialStore.Reference(name, version)))
                .isEqualTo("synthetic-private-payload");
        assertThatThrownBy(
                        () ->
                                store.get(
                                        new ConnectionCredentialStore.Reference(
                                                "another/application/secret", version)))
                .hasMessage("SOURCE_SECRET_REFERENCE_INVALID");
        assertThatThrownBy(() -> store.get(new ConnectionCredentialStore.Reference(name, "")))
                .hasMessage("SOURCE_SECRET_VERSION_INVALID");
        verify(client, times(1)).getSecretValue(any(Consumer.class));
    }

    @Test
    void schedulesExactlySevenDaysAndRestoresDuringRecovery() {
        Instant deadline = Instant.parse("2026-11-24T00:00:00Z");
        when(client.deleteSecret(any(Consumer.class)))
                .thenAnswer(
                        call -> {
                            DeleteSecretRequest.Builder request = DeleteSecretRequest.builder();
                            call.getArgument(0, Consumer.class).accept(request);
                            assertThat(request.build().secretId()).isEqualTo(name);
                            assertThat(request.build().recoveryWindowInDays()).isEqualTo(7L);
                            assertThat(request.build().forceDeleteWithoutRecovery()).isNull();
                            return DeleteSecretResponse.builder().deletionDate(deadline).build();
                        });
        when(client.describeSecret(any(Consumer.class)))
                .thenReturn(DescribeSecretResponse.builder().deletedDate(deadline).build());
        assertThat(store.scheduleDeletion(name)).isEqualTo(deadline);
        store.restore(name);
        verify(client).restoreSecret(any(Consumer.class));
    }

    @Test
    void sdkExceptionHasNoRawPayloadOrCauseAtTheBoundary() {
        when(client.getSecretValue(any(Consumer.class)))
                .thenThrow(new IllegalStateException("synthetic-private-payload"));
        assertThatThrownBy(() -> store.get(new ConnectionCredentialStore.Reference(name, version)))
                .hasMessage("SOURCE_CREDENTIAL_STORAGE_UNAVAILABLE")
                .hasNoCause();
    }

    @Test
    void refusesVersionMismatchInsteadOfSilentlyFollowingCurrentVersion() {
        when(client.getSecretValue(any(Consumer.class)))
                .thenReturn(
                        GetSecretValueResponse.builder()
                                .versionId("b".repeat(64))
                                .secretString("synthetic-private-payload")
                                .build());
        assertThatThrownBy(() -> store.get(new ConnectionCredentialStore.Reference(name, version)))
                .hasMessage("SOURCE_CREDENTIAL_STORAGE_UNAVAILABLE");
    }
}
