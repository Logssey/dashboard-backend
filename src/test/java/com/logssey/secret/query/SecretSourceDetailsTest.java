package com.logssey.secret.query;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class SecretSourceDetailsTest {
    @Test void githubLocationRequiresTheObservedBranchToRemainInCurrentScope() {
        var details=SecretSourceDetails.describeObserved("GITHUB","github://Logssey/project/main/",
                "github://Logssey/project/main/src/","OBSERVED","Logssey/project/src/app.java","L1");
        assertThat(details).containsEntry("branch","main").containsEntry("contextStatus","OBSERVED");
        assertThat(SecretSourceDetails.describeObserved("GITHUB","github://Logssey/project/develop/src/",
                "github://Logssey/project/main/src/","OBSERVED","Logssey/project/src/app.java","L1"))
                .containsEntry("status","UNAVAILABLE").containsEntry("reasonCode","SOURCE_APPROVAL_CHANGED");
        assertThat(SecretSourceDetails.describeObserved("GITHUB","github://Logssey/project/main/src/",
                null,"UNKNOWN","Logssey/project/src/app.java","L1"))
                .containsEntry("status","UNAVAILABLE").containsEntry("contextStatus","UNKNOWN");
    }
    @Test void notionLinksAreBoundToTheApprovedPageAndAnExactBlock() {
        String page="11111111-2222-3333-4444-555555555555",block="66666666-7777-8888-9999-aaaaaaaaaaaa";
        String ref="notion://pages/"+page;
        var value=SecretSourceDetails.describe("NOTION",ref,"notion/pages/"+page+"/blocks/"+block,"L2");
        assertThat(value).containsEntry("kind","NOTION_PAGE").containsEntry("pageId",page).containsEntry("blockId",block)
                .containsEntry("sourceUrl","https://www.notion.so/"+page.replace("-","")+"#"+block.replace("-",""));
        assertThat(SecretSourceDetails.describe("NOTION",ref,"notion/pages/"+block+"/blocks/"+block,"L2"))
                .containsEntry("status","UNAVAILABLE");
        assertThat(SecretSourceDetails.describe("NOTION",ref,"notion/pages/"+page+"/blocks/https://example.com","L2"))
                .containsEntry("status","UNAVAILABLE");
        assertThat(SecretSourceDetails.describe("NOTION",ref,"notion/pages/"+page+"/title","L1"))
                .containsEntry("sourceUrl","https://www.notion.so/"+page.replace("-",""));
    }

    @Test void restoresApprovedRepositoryFileBranchAndLineWithoutContents() {
        var value=SecretSourceDetails.describe("GITHUB","github://Logssey/test-find-key/main/fixtures/","Logssey/test-find-key/fixtures/config/sample.env","L4-7");
        assertThat(value).containsEntry("repository","Logssey/test-find-key").containsEntry("branch","main")
            .containsEntry("path","fixtures/config/sample.env").containsEntry("line","L4-7")
            .containsEntry("sourceUrl","https://github.com/Logssey/test-find-key/blob/main/fixtures/config/sample.env#L4-L7");
    }
    @Test void longDescriptiveFilenamesRetainTheirSourceLink() {
        String path="fixtures/VeryLongDescriptiveConfigurationFileNameForTheService.java";
        var value=SecretSourceDetails.describe("GITHUB","github://Logssey/test-find-key/main/fixtures/",
                "Logssey/test-find-key/"+path,"L1");
        assertThat(value).containsEntry("path",path);
        assertThat(value.get("sourceUrl")).isEqualTo("https://github.com/Logssey/test-find-key/blob/main/"+path+"#L1");
    }

    @Test void rejectsUnapprovedAndMalformedCoordinatesAndMasksCredentialLikeNames() {
        assertThat(SecretSourceDetails.describe("GITHUB","github://Logssey/test-find-key/main/fixtures/","Other/repo/fixtures/secret.env","L1")).containsEntry("status","UNAVAILABLE");
        assertThat(SecretSourceDetails.describe("GITHUB","github://token@Logssey/test-find-key/main/fixtures/","Logssey/test-find-key/fixtures/config.env","L1")).containsEntry("status","UNAVAILABLE");
        var key="ghp_"+"a".repeat(36);
        var value=SecretSourceDetails.describe("GITHUB","github://Logssey/test-find-key/main/fixtures/","Logssey/test-find-key/fixtures/"+key+".env","L1");
        assertThat(value.toString()).doesNotContain(key).contains("마스킹");
        assertThat(value.get("sourceUrl")).isNull();
    }
}
