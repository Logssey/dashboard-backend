package com.logssey.secret.query;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class SecretSourceDetailsTest {
    @Test void restoresApprovedRepositoryFileBranchAndLineWithoutContents() {
        var value=SecretSourceDetails.describe("GITHUB","github://Logssey/test-find-key/main/fixtures/","Logssey/test-find-key/fixtures/config/sample.env","L4-7");
        assertThat(value).containsEntry("repository","Logssey/test-find-key").containsEntry("branch","main")
            .containsEntry("path","fixtures/config/sample.env").containsEntry("line","L4-7")
            .containsEntry("sourceUrl","https://github.com/Logssey/test-find-key/blob/main/fixtures/config/sample.env#L4-L7");
    }
    @Test void rejectsUnapprovedAndMalformedCoordinatesAndMasksCredentialLikeNames() {
        assertThat(SecretSourceDetails.describe("GITHUB","github://Logssey/test-find-key/main/fixtures/","Other/repo/fixtures/secret.env","L1")).containsEntry("status","UNAVAILABLE");
        assertThat(SecretSourceDetails.describe("GITHUB","github://token@Logssey/test-find-key/main/fixtures/","Logssey/test-find-key/fixtures/config.env","L1")).containsEntry("status","UNAVAILABLE");
        var key="ghp_"+"a".repeat(36);
        var value=SecretSourceDetails.describe("GITHUB","github://Logssey/test-find-key/main/fixtures/","Logssey/test-find-key/fixtures/"+key+".env","L1");
        assertThat(value.toString()).doesNotContain(key).contains("마스킹");
        assertThat(value.get("sourceUrl")).isNull();
    }
    @Test void notionShowsOnlyTheApprovedPageAsAShortLabelAndLink() {
        String ref="notion://pages/0123456789abcdef0123456789abcdef";
        var value=SecretSourceDetails.describe("NOTION",ref,"notion/pages/01234567-89ab-cdef-0123-456789abcdef",null);
        assertThat(value).containsEntry("status","AVAILABLE").containsEntry("kind","NOTION_PAGE")
            .containsEntry("label","Notion 페이지 · 01234567…")
            .containsEntry("sourceUrl","https://www.notion.so/0123456789abcdef0123456789abcdef");
        assertThat(SecretSourceDetails.describe("NOTION",ref,"notion/pages/ffffffffffffffffffffffffffffffff",null))
            .containsEntry("status","UNAVAILABLE");
        assertThat(SecretSourceDetails.describe("NOTION","notion://workspace/all","notion/pages/x",null))
            .containsEntry("status","UNAVAILABLE");
        assertThat(SecretSourceDetails.scopeLabel("NOTION",ref,5)).isEqualTo("Notion 페이지 · 01234567…");
        assertThat(SecretSourceDetails.scopeLabel("NOTION","notion://pages/../all",5)).isEqualTo("검사 대상 #5");
    }
}
