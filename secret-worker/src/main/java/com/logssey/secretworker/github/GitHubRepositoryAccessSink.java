package com.logssey.secretworker.github;

/**
 * Optional adapter invoked after SUCCEEDED run_scope persistence inside its live-lease transaction.
 */
@FunctionalInterface
public interface GitHubRepositoryAccessSink {
    void observe(GitHubRepositoryAccessObservation observation);
}
