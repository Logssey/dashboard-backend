package com.logssey.secretworker.detector;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GitleaksDetectorTest {

    @Test
    void dropsEveryValueAndContextFieldFromToolReport() {
        String report = """
                [{"RuleID":"aws-access-token","StartLine":2,"EndLine":2,
                  "StartColumn":5,"EndColumn":24,"Secret":"raw-marker-must-not-escape",
                  "Match":"raw-marker-must-not-escape","File":"raw-marker-must-not-escape"}]
                """;

        var findings = GitleaksDetector.parseReport(report.getBytes(StandardCharsets.UTF_8));

        assertThat(findings).containsExactly(new GitleaksFinding("aws-access-token", 2, 2, 5, 24));
        assertThat(findings.toString()).doesNotContain("raw-marker-must-not-escape");
    }

    @Test
    void rejectsMalformedReportWithoutEchoingItsContents() {
        String malformed = "raw-marker-must-not-escape";

        assertThatThrownBy(() -> GitleaksDetector.parseReport(malformed.getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(DetectionFailure.class)
                .hasMessage("INVALID_REPORT")
                .hasMessageNotContaining(malformed);
    }

    @Test
    void rejectsInvalidRuleIdThatCouldCarryUntrustedText() {
        String report = """
                [{"RuleID":"raw marker must not escape","StartLine":1,"EndLine":1,
                  "StartColumn":1,"EndColumn":2}]
                """;

        assertThatThrownBy(() -> GitleaksDetector.parseReport(report.getBytes(StandardCharsets.UTF_8)))
                .isInstanceOf(DetectionFailure.class).hasMessage("INVALID_REPORT")
                .hasMessageNotContaining("raw marker must not escape");
    }

    @Test
    @EnabledIfEnvironmentVariable(named = "SECRET_GITLEAKS_PATH", matches = ".+")
    void scansSyntheticContentWithPinnedGitleaksWithoutReturningRawValue() throws Exception {
        String binary = System.getenv("SECRET_GITLEAKS_PATH");
        byte[] labelDigest = MessageDigest.getInstance("SHA-256")
                .digest("logssey-adapter-integration-fixture".getBytes(StandardCharsets.UTF_8));
        String symbols = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        var tail = new StringBuilder();
        for (int index = 0; index < 16; index++) {
            tail.append(symbols.charAt(Byte.toUnsignedInt(labelDigest[index]) % symbols.length()));
        }
        String id = "AKIA" + tail;
        byte[] content = ("aws_access_key_id = " + id + "\n").getBytes(StandardCharsets.UTF_8);

        var result = new GitleaksDetector(Path.of(binary)).scan(content);

        assertThat(result.engineVersion()).isEqualTo(GitleaksDetector.VERSION);
        assertThat(result.configHash()).hasSize(64);
        assertThat(result.findings()).anyMatch(finding -> finding.ruleId().equals("aws-access-token")
                && finding.startLine() == 1);
        assertThat(result.toString()).doesNotContain(id);
    }
}
