package com.logssey.help;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

/** Structural guarantees from the design: the chatbot cannot reach keys, findings or scan data. */
class HelpBoundaryTest {

    private static final Path SOURCE = Path.of("src/main/java/com/logssey/help");
    private static final Pattern FORBIDDEN_IMPORT = Pattern.compile(
            "import\\s+(static\\s+)?com\\.logssey\\.(secret|credential|runtime|reach|compliance|iac|overview|user|auth)\\.");
    private static final Pattern TABLE_REFERENCE = Pattern.compile(
            "(?i)\\b(?:FROM|INTO|UPDATE|JOIN|TABLE)\\s+([a-z][a-z0-9]*_[a-z0-9_]*)");

    /** Design doc 17: the only allowed outside import is the AWS credential helper, used by the key store only. */
    private static final String KEY_STORE = "HelpClaudeKeyStore.java";
    private static final String CREDENTIAL_HELPER = "import com.logssey.secret.aws.SecretAwsSourceCredentials;";

    @Test
    void helpPackageImportsNoDataModules() throws IOException {
        try (Stream<Path> files = Files.list(SOURCE)) {
            for (Path file : files.toList()) {
                String text = Files.readString(file);
                boolean keyStore = file.getFileName().toString().equals(KEY_STORE);
                if (keyStore) {
                    assertThat(text).contains(CREDENTIAL_HELPER);
                    text = text.replace(CREDENTIAL_HELPER, "");
                } else {
                    assertThat(text).as(file.toString()).doesNotContain("software.amazon.awssdk", "SecretAwsSourceCredentials");
                }
                assertThat(FORBIDDEN_IMPORT.matcher(text).find()).as(file.toString()).isFalse();
                assertThat(text).as(file.toString()).doesNotContain("Repository", "EntityManager");
            }
        }
    }

    @Test
    void helpPackageUsesNoDatabase() throws IOException {
        try (Stream<Path> files = Files.list(SOURCE)) {
            for (Path file : files.toList()) {
                String text = Files.readString(file);
                assertThat(text).as(file.toString())
                        .doesNotContain("JdbcTemplate", "JdbcClient", "DataSource", "jakarta.persistence");
                Set<String> tables = TABLE_REFERENCE.matcher(text).results()
                        .map(result -> result.group(1).toLowerCase()).collect(Collectors.toSet());
                assertThat(tables).as(file.toString()).isEmpty();
            }
        }
    }

    @Test
    void requestDeclaresNoToolsAndCarriesOnlyGuidesAndQuestion() {
        var provider = new ClaudeHelpProvider(true, "unused", "", "https://api.anthropic.com/v1/messages", 30_000,
                java.net.http.HttpClient.newBuilder().followRedirects(java.net.http.HttpClient.Redirect.NEVER).build(), false);
        var docs = List.of(new HelpDocument("a.md", "가이드", "# 가이드\n본문"));
        String body = provider.requestBody(docs, "키·노출 위치", List.of(), "질문입니다");

        assertThat(body).doesNotContain("\"tools\"", "tool_choice", "mcp_servers", "unused");
        assertThat(body).contains("\"citations\":{\"enabled\":true}", "cache_control", "현재 화면: 키·노출 위치", "질문입니다");
    }

    @Test
    void bundledGuidesMatchManifestAndContainNoSecrets() throws IOException, URISyntaxException {
        var library = new HelpDocumentLibrary();
        var entries = HelpDocumentLibrary.manifestEntries(getClass().getClassLoader());
        assertThat(library.documents()).hasSize(entries.size()).isNotEmpty();
        library.documents().forEach(doc ->
                assertThat(HelpQuestionGuard.containsSecretLikeValue(doc.text())).as(doc.file()).isFalse());

        Path folder = Path.of("src/main/resources/help-docs");
        try (Stream<Path> files = Files.list(folder)) {
            Set<String> onDisk = files.map(path -> path.getFileName().toString())
                    .filter(name -> !name.equals("manifest.txt")).collect(Collectors.toSet());
            assertThat(onDisk).containsExactlyInAnyOrderElementsOf(entries);
        }
    }
}
