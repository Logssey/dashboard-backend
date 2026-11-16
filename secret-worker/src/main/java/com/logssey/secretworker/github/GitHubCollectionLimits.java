package com.logssey.secretworker.github;

/** Fixed upper bounds; exceeding one is reported as missing coverage. */
public record GitHubCollectionLimits(int maxFiles, int maxTreeEntries, int maxDepth,
                                     long maxFileBytes, long maxTotalBytes, int maxJsonBytes) {
    public static final GitHubCollectionLimits DEFAULT =
            new GitHubCollectionLimits(
                    com.logssey.secret.connection.core.GitHubContentLimits.MAX_FILES,
                    com.logssey.secret.connection.core.GitHubContentLimits.MAX_TREE_ENTRIES,
                    com.logssey.secret.connection.core.GitHubContentLimits.MAX_DEPTH,
                    com.logssey.secret.connection.core.GitHubContentLimits.MAX_FILE_BYTES,
                    com.logssey.secret.connection.core.GitHubContentLimits.MAX_TOTAL_BYTES,
                    com.logssey.secret.connection.core.GitHubContentLimits.MAX_JSON_BYTES);

    public GitHubCollectionLimits {
        if (maxFiles < 1 || maxTreeEntries < 1 || maxDepth < 1 || maxFileBytes < 1
                || maxTotalBytes < maxFileBytes || maxJsonBytes < 1024) {
            throw new IllegalArgumentException("Invalid GitHub collection limits");
        }
    }
}
