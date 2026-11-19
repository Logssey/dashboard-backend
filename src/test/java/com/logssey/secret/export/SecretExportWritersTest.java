package com.logssey.secret.export;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import com.logssey.common.error.ApiException;
import tools.jackson.databind.json.JsonMapper;

class SecretExportWritersTest {
    private static final OffsetDateTime AT = OffsetDateTime.of(2026, 11, 19, 1, 2, 3, 0, ZoneOffset.UTC);
    private static final String PAGE = "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0";
    private static final String BLOCK = "11111111-2222-3333-4444-555555555555";

    private final JsonMapper json = JsonMapper.builder().build();

    @Test
    void sarifUsesPhysicalLocationForFilesAndLogicalLocationForNotion() {
        var sarif = SarifExportWriter.write(document());
        assertThat(sarif).containsEntry("version", "2.1.0").containsEntry("$schema", SarifExportWriter.SCHEMA);
        var run = (Map<?, ?>) ((List<?>) sarif.get("runs")).getFirst();
        var results = (List<?>) run.get("results");
        assertThat(results).hasSize(2);

        var github = (Map<?, ?>) results.get(0);
        assertThat(github.get("kind")).isEqualTo("fail");
        assertThat(github.get("level")).isEqualTo("error");
        assertThat(github.get("partialFingerprints")).isEqualTo(Map.of("logsseyOccurrence/v1", "101"));
        var githubLocation = (Map<?, ?>) ((List<?>) github.get("locations")).getFirst();
        var physical = (Map<?, ?>) githubLocation.get("physicalLocation");
        assertThat(((Map<?, ?>) physical.get("artifactLocation")).get("uri")).isEqualTo("fixtures/config/sample.env");
        assertThat(physical.get("region")).isEqualTo(Map.of("startLine", 4, "endLine", 6));

        var notion = (Map<?, ?>) results.get(1);
        var notionLocation = (Map<?, ?>) ((List<?>) notion.get("locations")).getFirst();
        assertThat(notionLocation.containsKey("physicalLocation")).isFalse();
        assertThat(notionLocation.get("logicalLocations").toString())
                .contains("notion/pages/" + PAGE + "/blocks/" + BLOCK, "kind=resource");
        assertThat(((Map<?, ?>) notion.get("message")).get("text").toString()).contains("notion/pages/" + PAGE);
        assertThat(((Map<?, ?>) notion.get("properties")).get("exposureRange")).isEqualTo("BROAD");
        assertThat(((Map<?, ?>) run.get("properties")).get("notice")).isEqualTo(SarifExportWriter.GITHUB_NOTICE);
        assertThat(json.writeValueAsString(sarif)).doesNotContain("null");
    }

    @Test
    void gitleaksMatchesDefectDojoCurrentFormatWithMaskedSecretOnly() {
        var items = GitleaksExportWriter.write(document());
        assertThat(items).hasSize(2);
        for (var item : items) {
            assertThat(item).containsKeys("Description", "File", "StartLine", "Secret", "Match", "RuleID", "Tags", "Fingerprint");
            assertThat(item.get("Description").toString()).isNotBlank();
            assertThat(item.get("Secret")).isEqualTo(item.get("Match")).isIn("AWS ••••1234", "Notion ••••abcd");
        }
        assertThat(items.get(0)).containsEntry("File", "Logssey/test-find-key/fixtures/config/sample.env")
                .containsEntry("StartLine", 4).containsEntry("EndLine", 6);
        assertThat(items.get(1)).containsEntry("File", "notion/pages/" + PAGE + "/blocks/" + BLOCK).containsEntry("StartLine", 0);
        assertThat(items.get(1).get("Tags").toString()).contains("exposure-range:BROAD");
    }

    @Test
    void logsseyJsonKeepsDocumentedFieldsAndSafeFilters() {
        var result = LogsseyJsonExportWriter.write(document());
        assertThat(result).containsEntry("schema", "logssey.secret-export").containsEntry("schemaVersion", "1.0")
                .containsEntry("keyCount", 2).containsEntry("locationCount", 2).containsEntry("restrictedCoverage", true);
        var item = (Map<?, ?>) ((List<?>) result.get("items")).get(1);
        assertThat(item.keySet().stream().map(Object::toString).toList()).containsExactly("credentialSetId", "occurrenceId", "maskedLabel", "issuer",
                "credentialType", "ruleId", "severity", "validationStatus", "source", "environment", "origin",
                "location", "exposure", "exposureRange", "presence", "actionStatus", "firstSeenAt", "lastSeenAt", "detectedAt");
        assertThat(((Map<?, ?>) item.get("location")).get("notionBlockId")).isEqualTo(BLOCK);
    }

    @Test
    void searchTextNeverReachesFiltersAndFilenamesCarryNoIdentity() {
        assertThat(SecretExportService.safeFilters(Map.of("origin", "PRODUCTION", "q", "결제 서버")))
                .containsEntry("hasSearch", "true").doesNotContainKey("q").doesNotContainValue("결제 서버");
        assertThat(SecretExportService.safeFilters(Map.of("origin", "PRODUCTION"))).containsEntry("hasSearch", "false");
        var date = LocalDate.of(2026, 11, 19);
        assertThat(SecretExportFormat.SARIF.filename(date)).isEqualTo("logssey-secrets-sarif-2026-11-19.sarif");
        assertThat(SecretExportFormat.LOGSSEY_JSON.filename(date)).isEqualTo("logssey-secrets-logssey-json-2026-11-19.json");
        assertThat(SecretExportFormat.GITLEAKS.filename(date)).isEqualTo("logssey-secrets-gitleaks-2026-11-19.json");
        assertThatThrownBy(() -> SecretExportFormat.parse("csv")).isInstanceOf(ApiException.class);
    }

    @Test
    void severityMapsToSarifLevels() {
        assertThat(SarifExportWriter.level("CRITICAL")).isEqualTo("error");
        assertThat(SarifExportWriter.level("MEDIUM")).isEqualTo("warning");
        assertThat(SarifExportWriter.level("LOW")).isEqualTo("note");
        assertThat(SarifExportWriter.level("UNASSESSED")).isEqualTo("warning");
    }

    private static SecretExportDocument document() {
        var github = new SecretExportRecord(1, 101, "AWS ••••1234", "AWS", "AWS_ACCESS_KEY_PAIR", "aws-access-token",
                "HIGH", "VALID", "GITHUB", "PROD", "PRODUCTION",
                new SecretExportRecord.Location("GITHUB_FILE", "Logssey/test-find-key/fixtures/config/sample.env",
                        "Logssey/test-find-key", "main", "fixtures/config/sample.env", 4, 6, null, null, null, null),
                "ABNORMAL", "UNKNOWN", "PRESENT", "OPEN", AT, AT, AT);
        var notion = new SecretExportRecord(2, 202, "Notion ••••abcd", "NOTION", "NOTION_INTEGRATION_TOKEN", "notion-token",
                "MEDIUM", "UNCHECKED", "NOTION", "UNKNOWN", "PRODUCTION",
                new SecretExportRecord.Location("NOTION_PAGE", "Notion 페이지 0f1e2d3c · 블록", null, null, null,
                        null, null, PAGE, BLOCK, null, null),
                "ABNORMAL", "BROAD", "PRESENT", "NO_CASE", AT, AT, null);
        return new SecretExportDocument(AT, AT, true, Map.of("origin", "PRODUCTION", "hasSearch", "false"), 2,
                List.of(github, notion));
    }
}
