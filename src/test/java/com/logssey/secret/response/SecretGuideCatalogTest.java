package com.logssey.secret.response;

import java.util.List;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SecretGuideCatalogTest {
    @Test
    void rejectsUnknownOrUnsafeOrderAndBoundsAllDisplayedCopy() {
        assertThat(SecretGuideCatalog.fromSelectedCodes(List.of("VERIFY_EXPOSURE",
                "EXTERNAL_ROTATION", "RECORD_ACTION", "REVALIDATE", "DELETE_EVERYTHING"))).isEmpty();
        assertThat(SecretGuideCatalog.fromSelectedCodes(List.of("VERIFY_EXPOSURE",
                "RECORD_ACTION", "EXTERNAL_ROTATION", "REVALIDATE"))).isEmpty();
        assertThat(SecretGuideCatalog.fromSelectedCodes(List.of("VERIFY_EXPOSURE",
                "EXTERNAL_ROTATION", "RECORD_ACTION", "REVALIDATE", "REVALIDATE"))).isEmpty();

        var guide = SecretGuideCatalog.fallback();
        assertThat(guide.steps()).hasSizeBetween(4, 6);
        assertThat(guide.title().length()).isLessThanOrEqualTo(80);
        assertThat(guide.notice().length()).isLessThanOrEqualTo(160);
        assertThat(guide.steps()).allSatisfy(step -> {
            assertThat(step.title().length()).isLessThanOrEqualTo(80);
            assertThat(step.description().length()).isLessThanOrEqualTo(160);
        });
    }
}
