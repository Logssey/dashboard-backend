package com.logssey.secret.notion;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/** The database stores a reference; only the externally configured file supplies its value. */
public final class SecretNotionSourceCredentials {
    public static final String REFERENCE = "notion-internal:default";
    private static final int MAX_BYTES = 512;
    private final Path path;

    private SecretNotionSourceCredentials(Path path) {
        if (path == null) throw unavailable();
        this.path = path.toAbsolutePath().normalize();
    }

    public static SecretNotionSourceCredentials file(Path path) {
        return new SecretNotionSourceCredentials(path);
    }

    public static boolean isReference(String reference) {
        return REFERENCE.equals(reference);
    }

    public String authRef() {
        return REFERENCE;
    }

    public String token() {
        byte[] bytes = null;
        try (var input = Files.newInputStream(path)) {
            bytes = input.readNBytes(MAX_BYTES + 1);
            if (bytes.length > MAX_BYTES) throw unavailable();
            String token = new String(bytes, StandardCharsets.UTF_8);
            if (token.startsWith("\uFEFF")) token = token.substring(1);
            token = token.strip();
            if (!token.matches("(?:ntn_[A-Za-z0-9_]{46}|secret_[A-Za-z0-9]{43})"))
                throw unavailable();
            return token;
        } catch (IOException | SecurityException ignored) {
            throw unavailable();
        } finally {
            if (bytes != null) Arrays.fill(bytes, (byte) 0);
        }
    }

    private static IllegalArgumentException unavailable() {
        return new IllegalArgumentException("NOTION_CREDENTIALS_UNAVAILABLE");
    }

    @Override
    public String toString() {
        return "SecretNotionSourceCredentials[redacted]";
    }
}
