package com.logssey.secret.response;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

class ClaudeApiKeySourceTest {
    @Test void readsCurrentManagedSecretWithoutConvertingItToAnApplicationRecord() {
        var client = mock(SecretsManagerClient.class);
        when(client.getSecretValue(any(Consumer.class))).thenReturn(
                GetSecretValueResponse.builder().secretString("synthetic-api-key\n").build());

        assertThat(ClaudeApiKeySource.read(client, "logssey/dashboard/ai/claude-api-key"))
                .isEqualTo("synthetic-api-key");
        var captor = ArgumentCaptor.forClass(Consumer.class);
        verify(client).getSecretValue(captor.capture());
        var builder = GetSecretValueRequest.builder();
        captor.getValue().accept(builder);
        assertThat(builder.build().versionStage()).isEqualTo("AWSCURRENT");
    }

    @Test void providerFailureAndMalformedValuesOnlyExposeAConstantReason() {
        var client = mock(SecretsManagerClient.class);
        when(client.getSecretValue(any(Consumer.class)))
                .thenThrow(new IllegalStateException("synthetic-sensitive-provider-body"));
        assertThatThrownBy(() -> ClaudeApiKeySource.read(client, "example"))
                .hasMessage("CLAUDE_KEY_STORE_UNAVAILABLE").hasNoCause();

        when(client.getSecretValue(any(Consumer.class))).thenReturn(
                GetSecretValueResponse.builder().secretString("invalid\r\nheader").build());
        assertThatThrownBy(() -> ClaudeApiKeySource.read(client, "example"))
                .hasMessage("CLAUDE_KEY_STORE_UNAVAILABLE").hasNoCause();
    }
}
