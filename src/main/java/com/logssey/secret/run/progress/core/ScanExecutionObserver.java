package com.logssey.secret.run.progress.core;

import java.util.function.Supplier;

/** Carries fixed operation facts only. Source content and exception messages never enter this API. */
@FunctionalInterface
public interface ScanExecutionObserver {
    ScanExecutionObserver NONE = (stage, operation, outcome, httpStatus, reason, count, total, duration) -> {};

    enum Stage { QUEUE, COLLECTION, DETECTION, VALIDATION, RESULT }
    enum Operation {
        RUN_REGISTERED, WORKER_CLAIM, RUN_RETRY, RUN_FINISHED, STAGE_SUMMARY,
        SCOPE_COLLECTION, GITHUB_REF_GET, GITHUB_COMMIT_GET, GITHUB_TREE_GET,
        GITHUB_BLOB_GET, GITHUB_REPOSITORY_GET, GITHUB_TOKEN_EXCHANGE,
        NOTION_PAGE_GET, NOTION_BLOCK_CHILDREN_LIST,
        AWS_GET_CALLER_IDENTITY, AWS_LIST_USERS, AWS_LIST_ACCESS_KEYS,
        AWS_GET_ACCESS_KEY_LAST_USED, AWS_GET_ACCOUNT_SUMMARY, AWS_LIST_SECRETS,
        AWS_DESCRIBE_PARAMETERS, AWS_LIST_BUCKETS, AWS_GET_SECRET_VALUE,
        AWS_GET_PARAMETER, AWS_HEAD_OBJECT, AWS_GET_OBJECT,
        GITLEAKS_SCAN, CANDIDATE_NORMALIZATION, FINDINGS_COMMIT,
        AWS_CREDENTIAL_CHECK, GITHUB_CREDENTIAL_CHECK, NOTION_CREDENTIAL_CHECK,
        CREDENTIAL_CHECK
    }
    enum Outcome { STARTED, COMPLETED, PARTIAL, FAILED, SKIPPED, RETRY_SCHEDULED, CANCELLED }

    void record(Stage stage, Operation operation, Outcome outcome, Integer httpStatus,
                String reasonCode, Long processedCount, Long totalCount, Long durationMs);

    default <T> T measure(Stage stage, Operation operation, Supplier<T> action) {
        record(stage, operation, Outcome.STARTED, null, null, null, null, null);
        long started = System.nanoTime();
        try {
            T result = action.get();
            record(stage, operation, Outcome.COMPLETED, null, null, null, null, elapsed(started));
            return result;
        } catch (RuntimeException failure) {
            record(stage, operation, Outcome.FAILED, null, "OPERATION_FAILED", null, null, elapsed(started));
            throw failure;
        }
    }

    static long elapsed(long started) {
        return Math.min(86_400_000L, Math.max(0L, (System.nanoTime() - started) / 1_000_000L));
    }
}
