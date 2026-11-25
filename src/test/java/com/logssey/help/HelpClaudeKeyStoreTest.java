package com.logssey.help;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.http.HttpClient;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

/** Design doc 17: the production key comes from Secrets Manager; it is cached and never required to be on disk. */
class HelpClaudeKeyStoreTest {

    private static final String KEY = "test-" + HelpTestKeys.random("abcdef0123456789", 24);

    private record Fake(HelpClaudeKeyStore store, AtomicInteger reads, AtomicReference<String> value, AtomicLong now) {
    }

    private static Fake fake(String initial) {
        var reads = new AtomicInteger();
        var value = new AtomicReference<>(initial);
        var now = new AtomicLong(1_000);
        var store = new HelpClaudeKeyStore(() -> {
            reads.incrementAndGet();
            String v = value.get();
            if ("THROW".equals(v)) throw new IllegalStateException("aws down");
            return v;
        }, now::get);
        return new Fake(store, reads, value, now);
    }

    @Test
    void goodKeyIsKeptForTenMinutes() {
        var fake = fake(" " + KEY + "\n");
        assertThat(fake.store().get()).isEqualTo(KEY);
        fake.now().addAndGet(HelpClaudeKeyStore.KEEP_KEY.toNanos() - 1);
        assertThat(fake.store().get()).isEqualTo(KEY);
        assertThat(fake.reads()).hasValue(1);
        fake.value().set(KEY + "x");
        fake.now().addAndGet(2);
        assertThat(fake.store().get()).isEqualTo(KEY + "x");
        assertThat(fake.reads()).hasValue(2);
    }

    @Test
    void failuresReturnNullAndAreRetriedAfterAMinute() {
        var fake = fake("THROW");
        assertThat(fake.store().get()).isNull();
        assertThat(fake.store().get()).isNull();
        assertThat(fake.reads()).hasValue(1);
        fake.value().set(KEY);
        fake.now().addAndGet(HelpClaudeKeyStore.KEEP_FAILURE.toNanos());
        assertThat(fake.store().get()).isEqualTo(KEY);
        for (String bad : new String[] {null, "", "has space", "한글키", "x".repeat(4_097)}) {
            var other = fake(bad);
            assertThat(other.store().get()).as(String.valueOf(bad)).isNull();
        }
    }

    @Test
    void secretsManagerNeedsAWellFormedSecretIdAndRegion() {
        assertThat(HelpClaudeKeyStore.secretsManager("", "ap-northeast-1", "WORKLOAD", "", "")).isNull();
        assertThat(HelpClaudeKeyStore.secretsManager(null, "ap-northeast-1", "WORKLOAD", "", "")).isNull();
        assertThat(HelpClaudeKeyStore.secretsManager("bad id with spaces", "ap-northeast-1", "WORKLOAD", "", "")).isNull();
        assertThat(HelpClaudeKeyStore.secretsManager("logssey/dashboard/ai/claude-api-key", "nowhere", "WORKLOAD", "", "")).isNull();
        // Building the store does not call AWS; only get() does.
        assertThat(HelpClaudeKeyStore.secretsManager("logssey/dashboard/ai/claude-api-key", "ap-northeast-1", "WORKLOAD", "", ""))
                .isNotNull();
    }

    @Test
    void providerUsesTheStoreOnlyWithoutADirectKeyAndReportsWhyItIsNotReady() {
        var http = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
        String url = "https://api.anthropic.com/v1/messages";
        var down = fake("THROW");
        var up = fake(KEY);

        assertThat(new ClaudeHelpProvider(true, "", "", down.store(), url, 30_000, http, false).configurationReason())
                .isEqualTo("KEY_STORE_UNAVAILABLE");
        assertThat(new ClaudeHelpProvider(true, "", "", up.store(), url, 30_000, http, false).configurationReason())
                .isEqualTo("READY");
        assertThat(new ClaudeHelpProvider(true, "", "", null, url, 30_000, http, false).configurationReason())
                .isEqualTo("KEY_MISSING");
        assertThat(new ClaudeHelpProvider(false, "", "", up.store(), url, 30_000, http, false).configurationReason())
                .isEqualTo("DISABLED");

        var direct = fake(KEY);
        assertThat(new ClaudeHelpProvider(true, "direct-" + KEY, "", direct.store(), url, 30_000, http, false)
                .configurationReason()).isEqualTo("READY");
        assertThat(direct.reads()).as("a direct key never touches Secrets Manager").hasValue(0);
    }

    /** Design doc 17.2: without any setting the team's Claude key name is used; a configured name still wins. */
    @Test
    void defaultsToTheTeamKeyNameButAConfiguredNameWins() throws java.io.IOException {
        String properties = java.nio.file.Files.readString(java.nio.file.Path.of("src/main/resources/application.properties"));
        assertThat(properties).contains("logssey.help.claude.key-secret-id=${HELP_CLAUDE_KEY_SECRET_ID:"
                + "${logssey.secret.guide.claude.api-key-secret-id:logssey/dashboard/ai/claude-api-key}}");
        assertThat(properties).doesNotContainPattern("(?i)sk-ant-");
    }
}
