package com.logssey.compliance;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class ComplianceCatalogTest {

    @Test
    void loadsAllReviewedFrameworkMappings() {
        var catalog = new ComplianceCatalog();

        assertThat(catalog.frameworks()).extracting(ComplianceCatalog.Framework::id)
                .containsExactly("isms", "iso", "csap");
        assertThat(catalog.framework("isms").controls()).hasSize(101);
        assertThat(catalog.framework("iso").controls()).hasSize(92);
        assertThat(catalog.framework("csap").controls()).hasSize(79);
        assertThat(mappingCount(catalog.framework("isms"))).isEqualTo(1259);
        assertThat(mappingCount(catalog.framework("iso"))).isEqualTo(867);
        assertThat(mappingCount(catalog.framework("csap"))).isEqualTo(734);
        assertThat(catalog.framework("csap").controls()).flatExtracting(ComplianceCatalog.Control::mappings)
                .allMatch(mapping -> mapping.applicability() != null && !mapping.applicability().isBlank());
        assertThat(catalog.source().prowlerVersion()).isEqualTo("5.46.0");
    }

    private static int mappingCount(ComplianceCatalog.Framework framework) {
        return framework.controls().stream().mapToInt(control -> control.mappings().size()).sum();
    }
}
