package com.logssey.secretworker.detection;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assumptions;

import com.logssey.secretworker.detector.GitleaksDetector;
import com.logssey.secretworker.detector.GitleaksFinding;

import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;

class SecretFindingNormalizerTest {
    private final SecretFindingNormalizer normalizer = new SecretFindingNormalizer(new byte[32], "test-v1");

    @Test
    void fullComponentIdentityDedupesAcrossLocationsButIncompleteCandidatesStayLocal() {
        String id = awsId("long-A", "AKIA");
        String secret = awsSecret("long-A");
        byte[] first = ("AWS_ACCESS_KEY_ID=" + id + "\nAWS_SECRET_ACCESS_KEY=" + secret + "\n")
                .getBytes(StandardCharsets.UTF_8);
        List<GitleaksFinding> pair = List.of(
                new GitleaksFinding("aws-access-token", 1, 1, 19, 38),
                new GitleaksFinding("generic-api-key", 2, 2, 1, 60));
        var a = normalizer.normalize(1, "repo/file-a", first, pair);
        var b = normalizer.normalize(1, "repo/file-b", first, pair);
        assertThat(a).hasSize(1);
        assertThat(a.getFirst().componentState()).isEqualTo("CONFIRMED");
        assertThat(a.getFirst().fingerprint()).isEqualTo(b.getFirst().fingerprint());

        byte[] incomplete = ("AWS_ACCESS_KEY_ID=" + id + "\n").getBytes(StandardCharsets.UTF_8);
        var candidateA = normalizer.normalize(1, "repo/file-a", incomplete, pair.subList(0, 1));
        var candidateB = normalizer.normalize(1, "repo/file-b", incomplete, pair.subList(0, 1));
        assertThat(candidateA.getFirst().componentState()).isEqualTo("CANDIDATE");
        assertThat(candidateA.getFirst().fingerprint()).isNull();
        assertThat(candidateA.getFirst().candidateLocator()).isNotEqualTo(candidateB.getFirst().candidateLocator());
        assertThat(a.toString()).doesNotContain(id, secret);
    }

    @Test
    void refusesAmbiguousPairEvenWhenIdsAndSecretsAppearInOrder() {
        String input = "AWS_ACCESS_KEY_ID=" + awsId("one", "AKIA") + "\n"
                + "AWS_SECRET_ACCESS_KEY=" + awsSecret("one") + "\n"
                + "AWS_ACCESS_KEY_ID=" + awsId("two", "AKIA") + "\n"
                + "AWS_SECRET_ACCESS_KEY=" + awsSecret("two") + "\n";
        var findings = List.of(
                new GitleaksFinding("aws-access-token", 1, 1, 19, 38),
                new GitleaksFinding("generic-api-key", 2, 2, 1, 60),
                new GitleaksFinding("aws-access-token", 3, 3, 19, 38),
                new GitleaksFinding("generic-api-key", 4, 4, 1, 60));
        var normalized = normalizer.normalize(1, "repo/ambiguous", input.getBytes(StandardCharsets.UTF_8), findings);
        assertThat(normalized).hasSize(4).allMatch(c -> c.componentState().equals("CANDIDATE"));
    }

    @Test
    void pairsByCompatibleFieldNamesRegardlessOfOrderAndUsesTheWholePairAsIdentity() {
        String id = awsId("qualified", "AKIA");
        String secret = awsSecret("qualified");
        String reversed = "AWS_PROD_SECRET_ACCESS_KEY=" + secret + "\n"
                + "AWS_PROD_ACCESS_KEY_ID=" + id + "\n";
        var findings = List.of(
                new GitleaksFinding("generic-api-key", 1, 1, 1, 64),
                new GitleaksFinding("aws-access-token", 2, 2, 24, 43));
        var matched = normalizer.normalize(1, "repo/qualified", reversed.getBytes(StandardCharsets.UTF_8), findings);
        assertThat(matched).hasSize(1);
        assertThat(matched.getFirst().componentState()).isEqualTo("CONFIRMED");

        String wrongQualifier = reversed.replace("AWS_PROD_ACCESS_KEY_ID", "AWS_DEV_ACCESS_KEY_ID");
        var separate = normalizer.normalize(1, "repo/qualified", wrongQualifier.getBytes(StandardCharsets.UTF_8), findings);
        assertThat(separate).hasSize(2).allMatch(c -> c.componentState().equals("CANDIDATE"));

        String changedSecret = reversed.replace(secret, awsSecret("other"));
        var different = normalizer.normalize(1, "repo/qualified", changedSecret.getBytes(StandardCharsets.UTF_8), findings);
        assertThat(different.getFirst().fingerprint()).isNotEqualTo(matched.getFirst().fingerprint());
    }

    @Test
    void temporaryAwsPairRequiresSessionToken() {
        String input = "AWS_ACCESS_KEY_ID=" + awsId("temp", "ASIA") + "\n"
                + "AWS_SECRET_ACCESS_KEY=" + awsSecret("temp") + "\n";
        var findings = List.of(
                new GitleaksFinding("aws-access-token", 1, 1, 19, 38),
                new GitleaksFinding("generic-api-key", 2, 2, 1, 60));
        var candidate = normalizer.normalize(1, "repo/temp", input.getBytes(StandardCharsets.UTF_8), findings);
        assertThat(candidate).hasSize(1);
        assertThat(candidate.getFirst().credentialType()).isEqualTo("AWS_TEMPORARY_CREDENTIALS");
        assertThat(candidate.getFirst().componentState()).isEqualTo("CANDIDATE");

        String completeInput = input + "AWS_SESSION_TOKEN=" + awsSecret("session") + "\n";
        var complete = normalizer.normalize(1, "repo/temp", completeInput.getBytes(StandardCharsets.UTF_8), findings);
        assertThat(complete.getFirst().componentState()).isEqualTo("CONFIRMED");
        assertThat(complete.getFirst().fingerprint()).hasSize(32);
    }

    @Test
    void normalizesThePublishedSyntheticCorpusWhenAvailable() throws Exception {
        Path fixtureRepo = workspaceArtifact("test-find-key");
        Path binary = workspaceArtifact("tools", "gitleaks", "gitleaks.exe");
        Assumptions.assumeTrue(Files.isRegularFile(fixtureRepo.resolve("expected-results.json"))
                && Files.isRegularFile(binary));
        var manifest = JsonMapper.builder().build().readTree(Files.readAllBytes(fixtureRepo.resolve("expected-results.json")));
        var detector = new GitleaksDetector(binary);
        List<SecretFindingNormalizer.Credential> all = new ArrayList<>();
        int positive = 0;
        int negative = 0;
        for (var fixture : manifest.path("fixtures")) {
            String relative = fixture.path("path").asText();
            byte[] bytes = Files.readAllBytes(fixtureRepo.resolve(relative));
            var scan = detector.scan(bytes);
            var found = normalizer.normalize(1, relative, bytes, scan.findings());
            if (fixture.path("negative").asBoolean()) {
                negative++;
                assertThat(found).as(relative).isEmpty();
            } else {
                positive++;
                assertThat(found).as(relative).hasSize(fixture.path("expectedOccurrences").size());
            }
            all.addAll(found);
            Arrays.fill(bytes, (byte) 0);
        }
        Set<String> confirmed = new HashSet<>();
        int candidates = 0;
        for (var credential : all) {
            if (credential.componentState().equals("CONFIRMED")) {
                confirmed.add(HexFormat.of().formatHex(credential.fingerprint()));
            } else {
                candidates++;
            }
        }
        assertThat(positive).isEqualTo(13);
        assertThat(negative).isEqualTo(3);
        assertThat(all).hasSize(15);
        assertThat(confirmed).hasSize(7);
        assertThat(candidates).isEqualTo(2);
    }

    @Test
    void notionCurrentAndLegacyTokensAreAvailableToValidationInProseAndCode() {
        String current = "ntn_" + "A".repeat(46);
        String legacy = "secret_" + "B".repeat(43);
        String prefix = "운영 문서에서 확인할 시험용 연결 정보입니다. 접근 여부를 확인할 토큰은 🔐 `";
        String text = prefix + current + "` 입니다.\nNOTION_TOKEN=" + legacy;
        int byteStart = prefix.getBytes(StandardCharsets.UTF_8).length + 1;
        var findings = List.of(
                new GitleaksFinding("notion-api-token", 1, 1,
                        byteStart, byteStart + current.length() - 1),
                new GitleaksFinding("notion-api-token", 2, 2, 14, 13 + legacy.length()));
        var inspection = normalizer.inspect(1, "repo/notion.txt",
                text.getBytes(StandardCharsets.UTF_8), findings);

        assertThat(inspection.credentials()).hasSize(2)
                .allMatch(c -> "NOTION".equals(c.issuer())
                        && "NOTION_CONNECTION_TOKEN".equals(c.credentialType()));
        assertThat(inspection.notionCandidates()).hasSize(2);
        assertThat(inspection.notionCandidates().getFirst().token()).isEqualTo(current);
        assertThat(inspection.notionCandidates().getLast().token()).isEqualTo(legacy);
        assertThat(inspection.credentials().getFirst().findings()).containsExactly(findings.getFirst());
        assertThat(inspection.toString() + inspection.notionCandidates())
                .doesNotContain(current, legacy);
    }

    @Test
    void notionSameKeyKeepsItsFingerprintAcrossTextFormsAndLocations() {
        String token = "ntn_" + "C".repeat(46);
        byte[] assigned = ("NOTION_TOKEN=" + token).getBytes(StandardCharsets.UTF_8);
        byte[] prose = ("Token `" + token + "`.").getBytes(StandardCharsets.UTF_8);
        var a = normalizer.inspect(1, "repo/config", assigned,
                List.of(new GitleaksFinding("notion-api-token", 1, 1, 14, 63)));
        var b = normalizer.inspect(1, "repo/doc", prose,
                List.of(new GitleaksFinding("notion-api-token", 1, 1, 8, 57)));
        assertThat(a.credentials()).hasSize(1);
        assertThat(b.credentials()).hasSize(1);
        assertThat(a.credentials().getFirst().fingerprint())
                .isEqualTo(b.credentials().getFirst().fingerprint());

        var changed = normalizer.inspect(1, "repo/doc",
                new String(prose, StandardCharsets.UTF_8).replace("C", "D").getBytes(StandardCharsets.UTF_8),
                List.of(new GitleaksFinding("notion-api-token", 1, 1, 8, 57)));
        assertThat(changed.credentials().getFirst().fingerprint())
                .isNotEqualTo(a.credentials().getFirst().fingerprint());
    }

    @Test
    void notionExtractionRequiresAnExactSupportedTokenAndUnambiguousDetectorSpan() {
        String token = "ntn_" + "E".repeat(46);
        for (String text : List.of("x" + token, token + "x", token.substring(0, 48))) {
            var inspection = normalizer.inspect(1, "repo/invalid", text.getBytes(StandardCharsets.UTF_8),
                    List.of(new GitleaksFinding("notion-api-token", 1, 1, 1, text.length())));
            assertThat(inspection.notionCandidates()).isEmpty();
        }
        String ambiguous = token + " " + token;
        var inspection = normalizer.inspect(1, "repo/ambiguous", ambiguous.getBytes(StandardCharsets.UTF_8),
                List.of(new GitleaksFinding("notion-api-token", 1, 1, 1, ambiguous.length())));
        assertThat(inspection.notionCandidates()).isEmpty();
    }

    @Test
    void githubPatValuesInNotionProseKeepTheSameIdentityAsConfigurationValues() {
        for (String token : List.of("ghp_" + "G".repeat(36), "github_pat_" + "H".repeat(70))) {
            String rule = token.startsWith("ghp_") ? "github-pat" : "github-fine-grained-pat";
            String prefix = "이 문서의 연결 정보를 확인할 때 사용하는 시험용 토큰입니다. 값은 `";
            int start = prefix.getBytes(StandardCharsets.UTF_8).length + 1;
            var prose = normalizer.inspect(1, "notion/pages/example/blocks/local",
                    (prefix + token + "`").getBytes(StandardCharsets.UTF_8),
                    List.of(new GitleaksFinding(rule, 1, 1, start, start + token.length() - 1)));
            var config = normalizer.inspect(1, "repo/config", ("TOKEN=" + token).getBytes(StandardCharsets.UTF_8),
                    List.of(new GitleaksFinding(rule, 1, 1, 7, 6 + token.length())));
            assertThat(prose.githubCandidates()).hasSize(1);
            assertThat(prose.credentials().getFirst().fingerprint())
                    .isEqualTo(config.credentials().getFirst().fingerprint());
            assertThat(prose.toString() + prose.githubCandidates()).doesNotContain(token);
        }
    }

    private static String awsId(String label, String prefix) {
        byte[] digest = sha(label);
        String alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        StringBuilder result = new StringBuilder(prefix);
        for (int index = 0; index < 16; index++) {
            result.append(alphabet.charAt(Byte.toUnsignedInt(digest[index]) % alphabet.length()));
        }
        return result.toString();
    }

    private static String awsSecret(String label) {
        byte[] digest = sha(label);
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        StringBuilder result = new StringBuilder();
        for (int index = 0; index < 40; index++) {
            result.append(alphabet.charAt(Byte.toUnsignedInt(digest[index % digest.length]) % alphabet.length()));
        }
        return result.toString();
    }

    private static byte[] sha(String label) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(label.getBytes(StandardCharsets.UTF_8));
        } catch (Exception error) {
            throw new IllegalStateException(error);
        }
    }

    private static Path workspaceArtifact(String first, String... rest) {
        Path current = Path.of("").toAbsolutePath();
        while (current != null) {
            Path path = current.resolveSibling(first);
            for (String segment : rest) path = path.resolve(segment);
            if (Files.exists(path)) return path.normalize();
            current = current.getParent();
        }
        return Path.of(first, rest).toAbsolutePath();
    }
}
