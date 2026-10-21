package com.logssey.secret.response;

import java.util.regex.Pattern;

/** Only current-commit repository directories recognized by the GitHub collector are triageable. */
public final class SecretGithubScopePolicy {
    private static final Pattern APPROVED_REF = Pattern.compile(
            "^github://([A-Za-z0-9-]{1,39})/([A-Za-z0-9_.-]{1,100})/[^/?#]+/(?:[^/?#]+/)+$");

    private SecretGithubScopePolicy() {
    }

    public static boolean approved(String contentType, String historyLimit, String approvedRef) {
        if (!"GITHUB_REPOSITORY_FILES".equals(contentType)
                || !"CURRENT_COMMIT_ONLY".equals(historyLimit) || approvedRef == null) return false;
        var match = APPROVED_REF.matcher(approvedRef);
        if (!match.matches()) return false;
        return !match.group(1).startsWith("-") && !match.group(1).endsWith("-")
                && !match.group(2).equals(".") && !match.group(2).equals("..");
    }

    static boolean syntheticFixture(String approvedRef) {
        if (approvedRef == null) return false;
        var match = APPROVED_REF.matcher(approvedRef);
        return match.matches() && "Logssey".equalsIgnoreCase(match.group(1))
                && "test-find-key".equalsIgnoreCase(match.group(2));
    }
}
