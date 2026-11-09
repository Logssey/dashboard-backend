package com.logssey.secret.notion;

import static org.assertj.core.api.Assertions.*;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SecretNotionSourceCredentialsTest {
    @TempDir Path directory;

    @Test void rereadsTheConfiguredFileAndKeepsItsPathAndValueOutOfDiagnostics() throws Exception {
        Path file=directory.resolve("configured-token.txt");
        String first="ntn_"+"A".repeat(46),second="secret_"+"B".repeat(43);
        Files.writeString(file,"\uFEFF"+first+"\n");
        var credentials=SecretNotionSourceCredentials.file(file);
        assertThat(credentials.authRef()).isEqualTo("notion-internal:default");
        assertThat(credentials.token()).isEqualTo(first);
        Files.writeString(file,second+"\r\n");
        assertThat(credentials.token()).isEqualTo(second);
        assertThat(credentials.toString()).doesNotContain(first,second,file.toString());
        assertThat(SecretNotionSourceCredentials.isReference(file.toString())).isFalse();
    }

    @Test void missingOversizedAndMalformedFilesHaveOneSafeFailure() throws Exception {
        Path file=directory.resolve("private-name.txt");
        var credentials=SecretNotionSourceCredentials.file(file);
        assertThatThrownBy(credentials::token).hasMessage("NOTION_CREDENTIALS_UNAVAILABLE");
        Files.writeString(file,"x".repeat(513));
        assertThatThrownBy(credentials::token).hasMessage("NOTION_CREDENTIALS_UNAVAILABLE");
        Files.writeString(file,"ntn_"+"A".repeat(46)+"\nextra");
        assertThatThrownBy(credentials::token).hasMessage("NOTION_CREDENTIALS_UNAVAILABLE");
    }
}
