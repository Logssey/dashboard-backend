package com.logssey.help;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Loads the approved usage guides from the classpath once at startup.
 * The chatbot never reads the file system, the database, GitHub or Notion at request time.
 */
@Component
class HelpDocumentLibrary {

    static final String ROOT = "help-docs/";
    static final String MANIFEST = ROOT + "manifest.txt";
    /** Rough upper bound (~150k tokens) before switching to keyword retrieval (design 4.2). */
    static final int MAX_TOTAL_CHARS = 300_000;
    private static final Pattern FILE_NAME = Pattern.compile("[a-z0-9][a-z0-9-]{0,60}\\.md");
    private static final Logger log = LoggerFactory.getLogger(HelpDocumentLibrary.class);

    private final List<HelpDocument> documents;

    HelpDocumentLibrary() {
        this(HelpDocumentLibrary.class.getClassLoader());
    }

    HelpDocumentLibrary(ClassLoader loader) {
        this.documents = load(loader);
    }

    List<HelpDocument> documents() {
        return documents;
    }

    static List<String> manifestEntries(ClassLoader loader) {
        String manifest = read(loader, MANIFEST);
        if (manifest == null) return List.of();
        var entries = new ArrayList<String>();
        for (String line : manifest.split("\n")) {
            String entry = line.strip();
            if (entry.isEmpty() || entry.startsWith("#")) continue;
            if (!FILE_NAME.matcher(entry).matches()) {
                throw new IllegalStateException("Invalid help document entry in manifest");
            }
            entries.add(entry);
        }
        return List.copyOf(entries);
    }

    private static List<HelpDocument> load(ClassLoader loader) {
        var result = new ArrayList<HelpDocument>();
        int total = 0;
        for (String entry : manifestEntries(loader)) {
            String text = read(loader, ROOT + entry);
            if (text == null) throw new IllegalStateException("Help document listed in manifest is missing: " + entry);
            text = text.replace("\r\n", "\n");
            if (HelpQuestionGuard.containsSecretLikeValue(text)) {
                throw new IllegalStateException("Help document contains a secret-like value: " + entry);
            }
            total += text.length();
            result.add(new HelpDocument(entry, title(text, entry), text));
        }
        if (total > MAX_TOTAL_CHARS) {
            log.warn("Help documents total {} chars; consider keyword retrieval", total);
        }
        log.info("Loaded {} help documents ({} chars)", result.size(), total);
        return List.copyOf(result);
    }

    private static String title(String text, String fallback) {
        for (String line : text.split("\n")) {
            if (line.startsWith("# ")) return line.substring(2).strip();
        }
        return fallback;
    }

    private static String read(ClassLoader loader, String path) {
        try (InputStream input = loader.getResourceAsStream(path)) {
            if (input == null) return null;
            String text = new String(input.readAllBytes(), StandardCharsets.UTF_8);
            return text.startsWith("﻿") ? text.substring(1) : text;
        } catch (IOException e) {
            throw new IllegalStateException("Help document unreadable: " + path, e);
        }
    }
}
