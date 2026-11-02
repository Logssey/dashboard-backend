package com.logssey.secretworker.notion;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class NotionApprovedScopeTest {
    private static final String ID = "0123456789abcdef0123456789abcdef";

    @Test
    void acceptsOnePageIdWithOrWithoutHyphensAndNormalizesIt() {
        var plain = NotionApprovedScope.fromApprovedRef("notion://pages/" + ID, "CURRENT_VERSION_ONLY");
        var hyphenated = NotionApprovedScope.fromApprovedRef(
                "notion://pages/01234567-89ab-cdef-0123-456789abcdef", "CURRENT_VERSION_ONLY");
        assertThat(plain).isEqualTo(hyphenated);
        assertThat(plain.pageId()).isEqualTo("01234567-89ab-cdef-0123-456789abcdef");
        assertThat(plain.sourceObjectRef()).isEqualTo("notion/pages/01234567-89ab-cdef-0123-456789abcdef");
    }

    @Test
    void rejectsAnythingThatCouldWidenOrRedirectTheScope() {
        for (String ref : new String[] {
                "notion://pages/" + ID + "/children",
                "notion://pages/" + ID + "?x=1",
                "notion://databases/" + ID,
                "https://www.notion.so/" + ID,
                "notion://pages/" + ID.toUpperCase(),
                "notion://pages/../" + ID,
                "notion://pages/"}) {
            assertThatThrownBy(() -> NotionApprovedScope.fromApprovedRef(ref, "CURRENT_VERSION_ONLY"))
                    .as(ref).isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> NotionApprovedScope.fromApprovedRef("notion://pages/" + ID, "ALL_HISTORY"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
