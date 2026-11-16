package com.logssey.compliance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import com.logssey.common.error.ApiException;

import org.junit.jupiter.api.Test;

class ProwlerOcsfNormalizerTest {

    private final ProwlerOcsfNormalizer normalizer = new ProwlerOcsfNormalizer(
            Clock.fixed(Instant.parse("2026-11-16T00:00:00Z"), ZoneOffset.UTC));

    @Test
    void normalizesDeduplicatesAndMasksAccountIdentifiers() {
        String json = """
                [
                  {
                    "metadata":{"event_code":"s3_bucket_public_access","product":{"name":"Prowler","version":"5.46.0"}},
                    "status_code":"FAIL",
                    "finding_info":{"uid":"arn:aws:s3:ap-northeast-2:123456789012:bucket/example","title":"Public bucket"},
                    "cloud":{"provider":"AWS"},
                    "resources":[{"uid":"123456789012","name":"account-123456789012","region":"ap-northeast-2"}],
                    "severity":"High",
                    "time_dt":"2026-11-15T10:00:00Z"
                  },
                  {
                    "metadata":{"event_code":"s3_bucket_public_access"},
                    "status_code":"PASS",
                    "finding_info":{"uid":"arn:aws:s3:ap-northeast-2:123456789012:bucket/example"},
                    "cloud":{"provider":"AWS"}
                  },
                  {"metadata":{},"status_code":"FAIL"}
                ]
                """;

        var imported = normalizer.normalize(json.getBytes(StandardCharsets.UTF_8), "prod");

        assertThat(imported.inputCount()).isEqualTo(3);
        assertThat(imported.results()).hasSize(1);
        assertThat(imported.duplicateCount()).isEqualTo(1);
        assertThat(imported.warningCount()).isEqualTo(1);
        var result = imported.results().values().iterator().next();
        assertThat(result.result()).isEqualTo("PASS");
        assertThat(result.fingerprint()).hasSize(64).doesNotContain("123456789012");
    }

    @Test
    void rejectsNonOcsfDocument() {
        assertThatThrownBy(() -> normalizer.normalize("{\"hello\":true}".getBytes(StandardCharsets.UTF_8), "prod"))
                .isInstanceOf(ApiException.class)
                .hasMessageContaining("findings/items");
    }
}
