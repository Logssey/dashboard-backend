package com.logssey.secretworker.github;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/** A single, explicitly approved repository directory at one branch's current commit. */
public record GitHubApprovedScope(String owner, String repository, String branch, String pathPrefix) {
    private static final Pattern OWNER = Pattern.compile("[A-Za-z0-9-]{1,39}");
    private static final Pattern REPOSITORY = Pattern.compile("[A-Za-z0-9_.-]{1,100}");

    public GitHubApprovedScope {
        if (owner == null || !OWNER.matcher(owner).matches() || owner.startsWith("-") || owner.endsWith("-")) {
            throw new IllegalArgumentException("Invalid GitHub owner");
        }
        if (repository == null || !REPOSITORY.matcher(repository).matches()
                || repository.equals(".") || repository.equals("..")) {
            throw new IllegalArgumentException("Invalid GitHub repository");
        }
        if (branch == null || branch.isBlank() || branch.startsWith("/") || branch.endsWith("/")
                || branch.contains("//") || branch.contains("..") || branch.contains("@{")
                || branch.chars().anyMatch(c -> c < 32 || c == 127 || c == '\\' || c == '?' || c == '#'
                || c == '*' || c == '[' || c == '~' || c == '^' || c == ':')) {
            throw new IllegalArgumentException("Invalid GitHub branch");
        }
        if (pathPrefix == null || !pathPrefix.isEmpty() && (pathPrefix.isBlank() || !pathPrefix.endsWith("/"))
                || pathPrefix.startsWith("/")) {
            throw new IllegalArgumentException("An approved directory prefix is required");
        }
        for (String segment : pathPrefix.isEmpty() ? List.<String>of()
                : List.of(pathPrefix.substring(0, pathPrefix.length() - 1).split("/", -1))) {
            if (segment.isBlank() || segment.equals(".") || segment.equals("..")
                    || segment.indexOf('\\') >= 0 || segment.chars().anyMatch(c -> c < 32 || c == 127)) {
                throw new IllegalArgumentException("Invalid approved directory prefix");
            }
        }
    }

    /** Parses the scheduler's approved_ref; encoded branch slashes must stay within the branch segment. */
    public static GitHubApprovedScope fromApprovedRef(String approvedRef, String historyLimit) {
        if (!"CURRENT_COMMIT_ONLY".equals(historyLimit)) {
            throw new IllegalArgumentException("Unsupported GitHub history range");
        }
        URI uri;
        try {
            uri = URI.create(approvedRef);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Invalid GitHub approved_ref");
        }
        if (!"github".equals(uri.getScheme()) || uri.getRawUserInfo() != null || uri.getPort() != -1
                || uri.getRawQuery() != null || uri.getRawFragment() != null || uri.getRawAuthority() == null
                || !uri.getRawAuthority().equals(uri.getHost()) || uri.getRawPath() == null) {
            throw new IllegalArgumentException("Invalid GitHub approved_ref");
        }
        String[] raw = uri.getRawPath().split("/", -1);
        if (raw.length < 4 || !raw[0].isEmpty() || !raw[raw.length - 1].isEmpty()) {
            throw new IllegalArgumentException("Invalid GitHub approved_ref path");
        }
        List<String> parts = Arrays.stream(raw).skip(1).limit(raw.length - 2L)
                .map(GitHubApprovedScope::decodeSegment).toList();
        return new GitHubApprovedScope(uri.getHost(), parts.get(0), parts.get(1),
                parts.size() == 2 ? "" : String.join("/", parts.subList(2, parts.size())) + "/");
    }

    private static String decodeSegment(String raw) {
        if (raw.isEmpty()) {
            throw new IllegalArgumentException("Empty GitHub approved_ref segment");
        }
        try {
            return URLDecoder.decode(raw.replace("+", "%2B"), StandardCharsets.UTF_8);
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("Invalid GitHub approved_ref segment");
        }
    }
}
