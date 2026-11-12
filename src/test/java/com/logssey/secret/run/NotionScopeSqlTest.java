package com.logssey.secret.run;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class NotionScopeSqlTest {
    @Test
    void acceptsOnlyOneExactPageAtItsCurrentVersion() {
        assertThat(NotionScopeSql.approved("NOTION_PAGE_CONTENT",
                "CURRENT_VERSION_ONLY", "notion://pages/0123456789abcdef0123456789abcdef")).isTrue();
        assertThat(NotionScopeSql.pageId("notion://pages/01234567-89ab-cdef-0123-456789abcdef"))
                .isEqualTo("0123456789abcdef0123456789abcdef");
        assertThat(NotionScopeSql.approved("NOTION_PAGE_CONTENT",
                "ALL_HISTORY", "notion://pages/0123456789abcdef0123456789abcdef")).isFalse();
        assertThat(NotionScopeSql.approved("GITHUB_REPOSITORY_FILES",
                "CURRENT_VERSION_ONLY", "notion://pages/0123456789abcdef0123456789abcdef")).isFalse();
        assertThat(NotionScopeSql.pageId("notion://pages/0123456789ABCDEF0123456789ABCDEF")).isNull();
        assertThat(NotionScopeSql.pageId("notion://pages/0123456789abcdef0123456789abcdef/children")).isNull();
        assertThat(NotionScopeSql.pageId(null)).isNull();
    }

    @Test
    void aliasIsNeverCallerInput() {
        assertThat(NotionScopeSql.predicate("s")).startsWith("(s.content_type = 'NOTION_PAGE_CONTENT'");
        assertThatThrownBy(() -> NotionScopeSql.predicate("s; DROP TABLE x"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
