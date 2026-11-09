package com.logssey.secretworker.detector;

import com.logssey.secretworker.detection.SecretFindingNormalizer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

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

    @Test
    @EnabledIfEnvironmentVariable(named = "SECRET_GITLEAKS_PATH", matches = ".+")
    void detectsAndNormalizesNotionFormatsInKoreanProseWithPinnedRules() {
        var tokens = List.of(
                syntheticToken("ntn_", 46),
                syntheticToken("secret_", 43),
                syntheticToken("ntn_", 46));
        tokens = List.of(tokens.get(0), tokens.get(1),
                tokens.get(2).substring(0, 24) + "_" + tokens.get(2).substring(25));
        String text = "이문서는실제운영환경에서사용하는연결정보를설명하기위해작성된시험문서입니다. 🔐 "
                + String.join(" ", tokens);
        var detector = new GitleaksDetector(Path.of(System.getenv("SECRET_GITLEAKS_PATH")));
        var normalizer = new SecretFindingNormalizer(new byte[32], "test-v1");

        var scan = detector.scan(text.getBytes(StandardCharsets.UTF_8));
        var inspection = normalizer.inspect(1, "repo/notion-prose.txt",
                text.getBytes(StandardCharsets.UTF_8), scan.findings());

        assertThat(scan.findings().stream()
                .filter(finding -> "notion-api-token".equals(finding.ruleId())).count()).isEqualTo(3);
        assertThat(inspection.credentials()).hasSize(3)
                .allMatch(credential -> "NOTION".equals(credential.issuer())
                        && "NOTION_CONNECTION_TOKEN".equals(credential.credentialType()));
        assertThat(inspection.notionCandidates()).hasSize(3);
        for (String token : tokens) {
            assertThat(inspection.notionCandidates().stream()
                    .anyMatch(candidate -> token.equals(candidate.token()))).isTrue();
            assertThat((scan.toString() + inspection + inspection.notionCandidates()).contains(token))
                    .isFalse();
        }
    }

    @Test
    @EnabledIfEnvironmentVariable(named = "SECRET_GITLEAKS_PATH", matches = ".+")
    void embeddedNotionRulesKeepExactTokenBoundariesAtNormalization() {
        var detector = new GitleaksDetector(Path.of(System.getenv("SECRET_GITLEAKS_PATH")));
        var normalizer = new SecretFindingNormalizer(new byte[32], "test-v1");
        String token = syntheticToken("ntn_", 46);
        for (String text : List.of("x" + token, token + "x")) {
            var scan = detector.scan(text.getBytes(StandardCharsets.UTF_8));
            var inspection = normalizer.inspect(1, "repo/notion-boundary.txt",
                    text.getBytes(StandardCharsets.UTF_8), scan.findings());
            assertThat(inspection.notionCandidates()).isEmpty();
        }
    }

    private static String syntheticToken(String prefix, int bodyLength) {
        var alphabet = new ArrayList<Character>();
        for (char symbol : "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray()) {
            alphabet.add(symbol);
        }
        Collections.shuffle(alphabet, new SecureRandom());
        var token = new StringBuilder(prefix);
        for (int index = 0; index < bodyLength; index++) {
            token.append(alphabet.get(index));
        }
        return token.toString();
    }
}
