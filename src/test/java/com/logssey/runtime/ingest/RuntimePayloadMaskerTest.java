package com.logssey.runtime.ingest;

import static org.assertj.core.api.Assertions.assertThat;

import com.logssey.runtime.ingest.RuntimePayloadMasker.MaskedPayload;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;

class RuntimePayloadMaskerTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final RuntimePayloadMasker masker = new RuntimePayloadMasker();

    @Test
    void masksSecretKeysAndCredentialFragmentsBeforePersistence() throws Exception {
        JsonNode source = objectMapper.readTree("""
                {
                  "authorization": "Bearer original-token",
                  "output_fields": {
                    "proc.cmdline": "curl -H authorization=Bearer-secret password=hello https://example.test",
                    "proc.name": "bash"
                  }
                }
                """);

        MaskedPayload result = masker.mask(source);
        String persisted = result.payload().toString();

        assertThat(persisted).doesNotContain("original-token", "Bearer-secret", "hello");
        assertThat(result.payload().path("authorization").asText()).isEqualTo("[REDACTED]");
        assertThat(result.maskedFields()).contains("$.authorization", "$.output_fields.proc.cmdline");
        assertThat(source.path("authorization").asText()).isEqualTo("Bearer original-token");
    }
}
