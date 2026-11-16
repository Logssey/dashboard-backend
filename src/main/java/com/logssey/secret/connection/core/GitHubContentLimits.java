package com.logssey.secret.connection.core;

/** Shared fixed collection budget used by worker execution and connection preparation. */
public final class GitHubContentLimits {
    public static final int MAX_FILES = 1000;
    public static final int MAX_TREE_ENTRIES = 20000;
    public static final int MAX_DEPTH = 32;
    public static final long MAX_FILE_BYTES = 1048576;
    public static final long MAX_TOTAL_BYTES = 16777216;
    public static final int MAX_JSON_BYTES = 2097152;
    private GitHubContentLimits() { }
}
