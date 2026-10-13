package com.logssey.secretworker.detector;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

import static com.logssey.secretworker.detector.DetectionFailure.Code;

/**
 * Runs pinned Gitleaks against one collected object through stdin. Only rule and
 * position metadata leaves this class; the detector report is never logged or saved.
 */
public final class GitleaksDetector implements SecretContentDetector {

    public static final String VERSION = "8.30.1";
    public static final int MAX_INPUT_BYTES = 1024 * 1024;
    public static final int MAX_REPORT_BYTES = 4 * 1024 * 1024;
    private static final Duration TIMEOUT = Duration.ofSeconds(20);
    private static final Pattern SAFE_RULE_ID = Pattern.compile("[A-Za-z0-9_.-]{1,120}");
    private static final JsonMapper JSON = JsonMapper.builder().build();

    private final Path executable;
    private final String configHash;

    public GitleaksDetector(Path executable) {
        if (executable == null || !Files.isRegularFile(executable)) {
            throw new DetectionFailure(Code.TOOL_UNAVAILABLE);
        }
        this.executable = executable.toAbsolutePath().normalize();
        verifyVersion();
        this.configHash = configurationHash();
    }

    public GitleaksScanResult scan(byte[] content) {
        if (content == null || content.length > MAX_INPUT_BYTES) {
            throw new DetectionFailure(Code.INPUT_TOO_LARGE);
        }
        Process process;
        try {
            process = builder("stdin", "--no-banner", "--no-color", "--log-level", "error",
                    "--redact=100", "--report-format=json", "--report-path=-", "--exit-code=0",
                    "--max-decode-depth=0").start();
        } catch (IOException error) {
            throw new DetectionFailure(Code.TOOL_UNAVAILABLE);
        }

        var tasks = Executors.newVirtualThreadPerTaskExecutor();
        try {
            Future<Boolean> writer = tasks.submit(() -> {
                try (var stdin = process.getOutputStream()) {
                    stdin.write(content);
                    return true;
                } catch (IOException ignored) {
                    return false;
                }
            });
            Future<byte[]> reader = tasks.submit(() -> readBounded(process));
            if (!process.waitFor(TIMEOUT.toMillis(), TimeUnit.MILLISECONDS)) {
                throw new DetectionFailure(Code.TOOL_TIMEOUT);
            }
            byte[] report;
            try {
                report = reader.get(1, TimeUnit.SECONDS);
                if (!writer.get(1, TimeUnit.SECONDS)) {
                    throw new DetectionFailure(Code.TOOL_IO_ERROR);
                }
            } catch (ExecutionException error) {
                if (error.getCause() instanceof OutputLimitExceeded) {
                    throw new DetectionFailure(Code.OUTPUT_TOO_LARGE);
                }
                throw new DetectionFailure(Code.TOOL_IO_ERROR);
            } catch (TimeoutException error) {
                throw new DetectionFailure(Code.TOOL_TIMEOUT);
            }
            if (process.exitValue() != 0) {
                throw new DetectionFailure(Code.TOOL_EXIT);
            }
            return new GitleaksScanResult(VERSION, configHash, parseReport(report));
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new DetectionFailure(Code.INTERRUPTED);
        } finally {
            process.destroyForcibly();
            tasks.close();
        }
    }

    public String configHash() {
        return configHash;
    }

    @Override
    public String engineVersion() {
        return VERSION;
    }

    static List<GitleaksFinding> parseReport(byte[] report) {
        try {
            JsonNode root = JSON.readTree(report);
            if (root == null || root.isNull()) {
                return List.of();
            }
            if (!root.isArray()) {
                throw new DetectionFailure(Code.INVALID_REPORT);
            }
            List<GitleaksFinding> findings = new ArrayList<>();
            for (JsonNode item : root) {
                if (!item.isObject()) {
                    throw new DetectionFailure(Code.INVALID_REPORT);
                }
                String rule = item.path("RuleID").asText();
                int startLine = positiveNumber(item, "StartLine");
                int endLine = positiveNumber(item, "EndLine");
                int startColumn = positiveNumber(item, "StartColumn");
                int endColumn = positiveNumber(item, "EndColumn");
                if (!SAFE_RULE_ID.matcher(rule).matches() || endLine < startLine
                        || (endLine == startLine && endColumn < startColumn)) {
                    throw new DetectionFailure(Code.INVALID_REPORT);
                }
                findings.add(new GitleaksFinding(rule, startLine, endLine, startColumn, endColumn));
            }
            return List.copyOf(findings);
        } catch (DetectionFailure error) {
            throw error;
        } catch (RuntimeException error) {
            // JSON parser exceptions may quote source text, which can contain a credential.
            throw new DetectionFailure(Code.INVALID_REPORT);
        }
    }

    private static int positiveNumber(JsonNode item, String field) {
        JsonNode number = item.path(field);
        int value = number.isIntegralNumber() ? number.asInt() : 0;
        if (value <= 0) {
            throw new DetectionFailure(Code.INVALID_REPORT);
        }
        return value;
    }

    private static byte[] readBounded(Process process) throws IOException {
        try (InputStream output = process.getInputStream(); var buffer = new ByteArrayOutputStream()) {
            byte[] chunk = new byte[8192];
            int read;
            while ((read = output.read(chunk)) != -1) {
                if (buffer.size() + read > MAX_REPORT_BYTES) {
                    process.destroyForcibly();
                    throw new OutputLimitExceeded();
                }
                buffer.write(chunk, 0, read);
            }
            return buffer.toByteArray();
        }
    }

    private ProcessBuilder builder(String... arguments) {
        List<String> command = new ArrayList<>();
        command.add(executable.toString());
        command.addAll(List.of(arguments));
        ProcessBuilder builder = new ProcessBuilder(command).redirectError(ProcessBuilder.Redirect.DISCARD);
        builder.environment().remove("GITLEAKS_CONFIG");
        builder.environment().remove("GITLEAKS_CONFIG_TOML");
        return builder;
    }

    private void verifyVersion() {
        Process process = null;
        try {
            process = builder("version").start();
            if (!process.waitFor(10, TimeUnit.SECONDS)) {
                throw new DetectionFailure(Code.TOOL_TIMEOUT);
            }
            String actual = new String(process.getInputStream().readNBytes(80), StandardCharsets.UTF_8)
                    .trim().replaceFirst("^v", "");
            if (process.exitValue() != 0 || !VERSION.equals(actual)) {
                throw new DetectionFailure(Code.UNSUPPORTED_VERSION);
            }
        } catch (IOException error) {
            throw new DetectionFailure(Code.TOOL_UNAVAILABLE);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            throw new DetectionFailure(Code.INTERRUPTED);
        } finally {
            if (process != null) {
                process.destroyForcibly();
            }
        }
    }

    private String configurationHash() {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update("stdin:embedded-defaults:decode-depth-0:redact-100:".getBytes(StandardCharsets.UTF_8));
            try (InputStream binary = Files.newInputStream(executable)) {
                byte[] chunk = new byte[8192];
                int read;
                while ((read = binary.read(chunk)) != -1) {
                    digest.update(chunk, 0, read);
                }
            }
            return HexFormat.of().formatHex(digest.digest());
        } catch (IOException | NoSuchAlgorithmException error) {
            throw new DetectionFailure(Code.TOOL_UNAVAILABLE);
        }
    }

    private static final class OutputLimitExceeded extends IOException {
    }
}
