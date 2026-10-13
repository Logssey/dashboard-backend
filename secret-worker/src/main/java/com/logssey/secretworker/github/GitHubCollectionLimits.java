package com.logssey.secretworker.github;

/** Fixed upper bounds; exceeding one is reported as missing coverage. */
public record GitHubCollectionLimits(int maxFiles, int maxTreeEntries, int maxDepth,
                                     long maxFileBytes, long maxTotalBytes, int maxJsonBytes) {
    public static final GitHubCollectionLimits DEFAULT =
            new GitHubCollectionLimits(1_000, 20_000, 32, 1_048_576, 16_777_216, 2_097_152);

    public GitHubCollectionLimits {
        if (maxFiles < 1 || maxTreeEntries < 1 || maxDepth < 1 || maxFileBytes < 1
                || maxTotalBytes < maxFileBytes || maxJsonBytes < 1024) {
            throw new IllegalArgumentException("Invalid GitHub collection limits");
        }
    }
}
