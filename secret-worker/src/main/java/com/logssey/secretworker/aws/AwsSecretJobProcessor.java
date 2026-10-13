package com.logssey.secretworker.aws;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

import org.springframework.jdbc.core.JdbcTemplate;

import com.logssey.secretworker.ClaimedSecretJob;
import com.logssey.secretworker.SecretJobExecutionService;
import com.logssey.secretworker.SecretJobFailure;
import com.logssey.secretworker.SecretJobFailureCode;
import com.logssey.secretworker.SecretJobProcessor;
import com.logssey.secretworker.SecretJobProperties;
import com.logssey.secretworker.aws.content.AwsContentPipeline;
import com.logssey.secretworker.aws.content.AwsContentCollector;
import com.logssey.secretworker.aws.content.AwsContentScope;
import com.logssey.secretworker.aws.metadata.AwsMetadataApprovedScope;
import com.logssey.secretworker.aws.metadata.AwsMetadataCollector;

/** Runs approved AWS metadata scopes and separately opted-in exact value scopes. */
public final class AwsSecretJobProcessor implements SecretJobProcessor {
    private final JdbcTemplate jdbc;
    private final AwsIamCollector collector;
    private final AwsMetadataCollector additional;
    private final AwsIamGateway accountGateway;
    private final AwsIamMetadataRepository metadata;
    private final AwsContentPipeline content;
    private final SecretJobProperties jobs;
    private final String expectedAuthRef;

    public AwsSecretJobProcessor(JdbcTemplate jdbc, AwsIamCollector collector,
                                 AwsMetadataCollector additional, AwsIamGateway accountGateway,
                                 AwsIamMetadataRepository metadata, SecretJobProperties jobs,
                                 String profile) {
        this(jdbc, collector, additional, accountGateway, metadata, jobs, profile, null);
    }

    public AwsSecretJobProcessor(JdbcTemplate jdbc, AwsIamCollector collector,
                                 AwsMetadataCollector additional, AwsIamGateway accountGateway,
                                 AwsIamMetadataRepository metadata, SecretJobProperties jobs,
                                 String profile, AwsContentPipeline content) {
        this.jdbc = jdbc;
        this.collector = collector;
        this.additional = additional;
        this.accountGateway = accountGateway;
        this.metadata = metadata;
        this.content = content;
        this.jobs = jobs;
        if (profile == null || !profile.matches("[A-Za-z0-9._-]{1,100}")) {
            throw new IllegalArgumentException("AWS_PROFILE_REQUIRED");
        }
        this.expectedAuthRef = "aws-profile:" + profile;
    }

    @Override public String provider() { return "AWS"; }

    @Override
    public void process(ClaimedSecretJob job, SecretJobExecutionService execution) {
        var heartbeat = Executors.newSingleThreadScheduledExecutor(
                Thread.ofVirtual().name("aws-job-lease-heartbeat").factory());
        var leaseLost = new AtomicBoolean();
        long interval = Math.max(1_000L, jobs.leaseDuration().toMillis() / 3);
        var task = heartbeat.scheduleWithFixedDelay(() -> {
            try {
                if (!execution.renewLease(job.jobId(), job.leaseToken())) leaseLost.set(true);
            } catch (RuntimeException error) {
                leaseLost.set(true);
            }
        }, interval, interval, TimeUnit.MILLISECONDS);
        try {
            processScopes(job, execution, leaseLost);
        } finally {
            task.cancel(true);
            heartbeat.shutdownNow();
        }
    }

    private void processScopes(ClaimedSecretJob job, SecretJobExecutionService execution,
                               AtomicBoolean leaseLost) {
        List<Scope> scopes = jdbc.query("""
                SELECT rs.run_scope_id, s.scope_id, s.content_type, s.approved_ref,
                       s.history_limit, s.enabled, c.scope_version,
                       r.scope_version AS run_scope_version, c.status, c.auth_ref
                FROM secret_scan_runs r
                JOIN secret_connections c ON c.connection_id = r.connection_id
                JOIN secret_run_scopes rs ON rs.run_id = r.run_id
                JOIN secret_connection_scopes s ON s.scope_id = rs.scope_id
                    AND s.connection_id = c.connection_id
                WHERE r.run_id = ? AND r.job_id = ? AND r.connection_id = ? AND c.provider = 'AWS'
                ORDER BY rs.run_scope_id
                """, (rs, row) -> new Scope(rs.getLong("run_scope_id"), rs.getLong("scope_id"),
                rs.getString("content_type"), rs.getString("approved_ref"),
                rs.getString("history_limit"), rs.getBoolean("enabled"),
                rs.getLong("scope_version"), rs.getLong("run_scope_version"),
                rs.getString("status"), rs.getString("auth_ref")),
                job.runId(), job.jobId(), job.connectionId());
        if (scopes.isEmpty() || scopes.stream().anyMatch(scope -> !scope.enabled()
                || !"ACTIVE".equals(scope.connectionStatus())
                || !expectedAuthRef.equals(scope.authRef())
                || scope.connectionVersion() != scope.runVersion())) {
            throw new SecretJobFailure(SecretJobFailureCode.SOURCE_ACCESS_DENIED, false);
        }
        withLease(job, execution, () -> jdbc.update("""
                UPDATE secret_scan_runs SET collection_status = 'RUNNING',
                    detection_status = 'SKIPPED', validation_status = 'SKIPPED'
                WHERE run_id = ?
                """, job.runId()));

        int succeeded = 0;
        String firstGap = null;
        boolean allSucceeded = true;
        AccountCheck account = new AccountCheck();
        ContentProgress contentProgress = new ContentProgress();
        AwsContentPipeline.RunValidation validation = new AwsContentPipeline.RunValidation();
        for (Scope scope : scopes) {
            if (leaseLost.get()) throw new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
            ScopeResult result = processScope(job, scope, execution, account, contentProgress, validation);
            if (result.usable()) succeeded++;
            if (!result.complete()) allSucceeded = false;
            if (firstGap == null) firstGap = result.gap();
        }
        String collectionStatus = succeeded == 0 ? "FAILED" : allSucceeded ? "SUCCEEDED" : "PARTIAL";
        String safeGap = firstGap;
        boolean complete = allSucceeded;
        String detectionStatus = contentProgress.detectionStatus(succeeded > 0);
        String validationStatus = validation.status();
        String runGap = complete && "PARTIAL".equals(validationStatus)
                ? validation.failureCode() : complete ? null : safeGap;
        withLease(job, execution, () -> jdbc.update("""
                UPDATE secret_scan_runs SET collection_status = ?, detection_status = ?,
                    validation_status = ?, failure_code = ?
                WHERE run_id = ?
                """, collectionStatus, detectionStatus, validationStatus, runGap, job.runId()));
        if (succeeded == 0) {
            throw new SecretJobFailure(retryCode(firstGap), retryable(firstGap));
        }
    }

    private ScopeResult processScope(ClaimedSecretJob job, Scope scope,
                                     SecretJobExecutionService execution, AccountCheck account,
                                     ContentProgress contentProgress,
                                     AwsContentPipeline.RunValidation validation) {
        if (AwsContentScope.supports(scope.contentType())) {
            return processContentScope(job, scope, execution, account, contentProgress, validation);
        }
        if (AwsMetadataApprovedScope.supports(scope.contentType())) {
            return processAdditionalScope(job, scope, execution, account);
        }
        if (!"IAM_ACCESS_KEY_METADATA".equals(scope.contentType())) {
            finishScope(job, execution, scope.runScopeId(), "SKIPPED", 0,
                    "AWS_SERVICE_UNSUPPORTED", "AWS_SERVICE_UNSUPPORTED");
            return new ScopeResult(false, false, "AWS_SERVICE_UNSUPPORTED");
        }
        AwsApprovedScope approved;
        try {
            approved = AwsApprovedScope.parse(scope.contentType(), scope.approvedRef(),
                    scope.historyLimit());
        } catch (IllegalArgumentException error) {
            finishScope(job, execution, scope.runScopeId(), "FAILED", 0,
                    "AWS_INVALID_APPROVED_SCOPE", null);
            return new ScopeResult(false, false, "AWS_INVALID_APPROVED_SCOPE");
        }
        withLease(job, execution, () -> jdbc.update("""
                UPDATE secret_run_scopes SET collection_status = 'RUNNING',
                    started_at = COALESCE(started_at, ?), finished_at = NULL,
                    object_count = NULL, failure_code = NULL, unsupported_reason = NULL
                WHERE run_scope_id = ?
                """, now(), scope.runScopeId()));
        AwsIamCollector.Result result = collector.collect(approved, (key, usage) -> {
            if (!execution.renewLease(job.jobId(), job.leaseToken())
                    || !metadata.recordIfLeased(job, execution, scope.scopeId(), approved, key, usage)) {
                throw new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
            }
        });
        String gap = result.gaps().isEmpty() ? null : "AWS_" + result.gaps().getFirst().name();
        if (result.status() == AwsIamCollector.Status.SUCCEEDED
                && !metadata.markCompleteCoverageIfLeased(job, execution, scope.scopeId())) {
            throw new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
        }
        String coverage = result.gaps().stream()
                .filter(code -> code == AwsIamCollector.GapCode.ROOT_ACCESS_KEYS_PRESENT
                        || code == AwsIamCollector.GapCode.ROOT_KEY_COVERAGE_UNKNOWN)
                .findFirst().map(code -> "AWS_" + code.name()).orElse(null);
        finishScope(job, execution, scope.runScopeId(), result.status().name(),
                result.objectCount(), gap, coverage);
        return new ScopeResult(result.status() == AwsIamCollector.Status.SUCCEEDED
                || result.status() == AwsIamCollector.Status.PARTIAL,
                result.status() == AwsIamCollector.Status.SUCCEEDED, gap);
    }

    private ScopeResult processContentScope(ClaimedSecretJob job, Scope scope,
                                            SecretJobExecutionService execution, AccountCheck account,
                                            ContentProgress progress,
                                            AwsContentPipeline.RunValidation validation) {
        AwsContentScope approved;
        try {
            approved = AwsContentScope.fromApprovedRef(scope.contentType(), scope.approvedRef(),
                    scope.historyLimit());
        } catch (IllegalArgumentException error) {
            progress.failed();
            finishScope(job, execution, scope.runScopeId(), "FAILED", 0,
                    "AWS_INVALID_APPROVED_SCOPE", null);
            return new ScopeResult(false, false, "AWS_INVALID_APPROVED_SCOPE");
        }
        if (content == null) {
            progress.disabled();
            finishScope(job, execution, scope.runScopeId(), "SKIPPED", 0,
                    "AWS_CONTENT_READ_DISABLED", null);
            return new ScopeResult(false, false, "AWS_CONTENT_READ_DISABLED");
        }
        String accountGap = account.check(approved.accountId());
        if (accountGap != null) {
            progress.failed();
            finishScope(job, execution, scope.runScopeId(), "FAILED", 0, accountGap, null);
            return new ScopeResult(false, false, accountGap);
        }
        withLease(job, execution, () -> jdbc.update("""
                UPDATE secret_run_scopes SET collection_status = 'RUNNING',
                    started_at = COALESCE(started_at, ?), finished_at = NULL,
                    object_count = NULL, failure_code = NULL, unsupported_reason = NULL
                WHERE run_scope_id = ?
                """, now(), scope.runScopeId()));
        AwsContentPipeline.Result result;
        try {
            // Fence immediately before an API that can return sensitive value bytes.
            if (!execution.renewLease(job.jobId(), job.leaseToken())) {
                throw new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
            }
            result = content.process(job, execution, scope.scopeId(), scope.runScopeId(),
                    approved, validation);
        } catch (SecretJobFailure error) {
            throw error;
        } catch (RuntimeException error) {
            progress.failed();
            finishScope(job, execution, scope.runScopeId(), "FAILED", 0,
                    "AWS_CONTENT_PROCESSING_FAILED", null);
            return new ScopeResult(false, false, "AWS_CONTENT_PROCESSING_FAILED");
        }
        boolean success = result.status() == AwsContentCollector.Status.SUCCEEDED;
        if (success) progress.scanned(); else progress.failed();
        finishScope(job, execution, scope.runScopeId(), result.status().name(),
                result.objectCount(), result.gapCode(), null);
        return new ScopeResult(success, success, result.gapCode());
    }

    private ScopeResult processAdditionalScope(ClaimedSecretJob job, Scope scope,
                                               SecretJobExecutionService execution,
                                               AccountCheck account) {
        AwsMetadataApprovedScope approved;
        try {
            approved = AwsMetadataApprovedScope.parse(scope.contentType(), scope.approvedRef(),
                    scope.historyLimit());
        } catch (IllegalArgumentException error) {
            finishScope(job, execution, scope.runScopeId(), "FAILED", 0,
                    "AWS_INVALID_APPROVED_SCOPE", null);
            return new ScopeResult(false, false, "AWS_INVALID_APPROVED_SCOPE");
        }
        String accountGap = account.check(approved.accountId());
        if (accountGap != null) {
            finishScope(job, execution, scope.runScopeId(), "FAILED", 0, accountGap, null);
            return new ScopeResult(false, false, accountGap);
        }
        withLease(job, execution, () -> jdbc.update("""
                UPDATE secret_run_scopes SET collection_status = 'RUNNING',
                    started_at = COALESCE(started_at, ?), finished_at = NULL,
                    object_count = NULL, failure_code = NULL, unsupported_reason = NULL
                WHERE run_scope_id = ?
                """, now(), scope.runScopeId()));
        AwsMetadataCollector.Result result = additional.collect(approved.service(), approved.region());
        String gap = result.gaps().isEmpty() ? null : "AWS_" + result.gaps().getFirst().name();
        finishScope(job, execution, scope.runScopeId(), result.status().name(),
                result.objectCount(), gap, null);
        return new ScopeResult(result.status() == AwsMetadataCollector.Status.SUCCEEDED
                || result.status() == AwsMetadataCollector.Status.PARTIAL,
                result.status() == AwsMetadataCollector.Status.SUCCEEDED, gap);
    }

    private final class AccountCheck {
        private boolean checked;
        private String profileAccountId;
        private String failure;

        String check(String expected) {
            if (!checked) {
                checked = true;
                try {
                    profileAccountId = accountGateway.accountId();
                } catch (AwsIamSourceException error) {
                    failure = switch (error.code()) {
                        case ACCESS_DENIED -> "AWS_ACCESS_DENIED";
                        case RATE_LIMITED -> "AWS_RATE_LIMITED";
                        case UNAVAILABLE, INVALID_RESPONSE -> "AWS_SOURCE_UNAVAILABLE";
                    };
                } catch (RuntimeException error) {
                    failure = "AWS_SOURCE_UNAVAILABLE";
                }
            }
            if (failure != null) return failure;
            return expected.equals(profileAccountId) ? null : "AWS_ACCOUNT_MISMATCH";
        }
    }

    private void finishScope(ClaimedSecretJob job, SecretJobExecutionService execution,
                             long runScopeId, String status, int count,
                             String failure, String unsupported) {
        withLease(job, execution, () -> jdbc.update("""
                UPDATE secret_run_scopes SET collection_status = ?, object_count = ?,
                    failure_code = ?, unsupported_reason = ?, finished_at = ?
                WHERE run_scope_id = ?
                """, status, count, failure, unsupported, now(), runScopeId));
    }

    private static void withLease(ClaimedSecretJob job, SecretJobExecutionService execution,
                                  Runnable write) {
        if (!execution.persistIfLeased(job.jobId(), job.leaseToken(), write)) {
            throw new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
        }
    }

    private static OffsetDateTime now() { return Instant.now().atOffset(ZoneOffset.UTC); }

    private static SecretJobFailureCode retryCode(String gap) {
        if ("AWS_RATE_LIMITED".equals(gap) || "AWS_CONTENT_RATE_LIMITED".equals(gap)) {
            return SecretJobFailureCode.SOURCE_RATE_LIMITED;
        }
        if ("AWS_UNAVAILABLE".equals(gap) || "AWS_SOURCE_UNAVAILABLE".equals(gap)
                || "AWS_CONTENT_SOURCE_UNAVAILABLE".equals(gap)
                || "AWS_CONTENT_PROCESSING_FAILED".equals(gap)) {
            return SecretJobFailureCode.SOURCE_UNAVAILABLE;
        }
        return SecretJobFailureCode.SOURCE_ACCESS_DENIED;
    }

    private static boolean retryable(String gap) {
        return "AWS_RATE_LIMITED".equals(gap) || "AWS_UNAVAILABLE".equals(gap)
                || "AWS_SOURCE_UNAVAILABLE".equals(gap)
                || "AWS_CONTENT_RATE_LIMITED".equals(gap)
                || "AWS_CONTENT_SOURCE_UNAVAILABLE".equals(gap)
                || "AWS_CONTENT_PROCESSING_FAILED".equals(gap);
    }

    private static final class ContentProgress {
        private int scanned;
        private int failed;
        private int disabled;

        void scanned() { scanned++; }
        void failed() { failed++; }
        void disabled() { disabled++; }

        String detectionStatus(boolean anyUsableScope) {
            if (scanned == 0 && failed == 0) return "SKIPPED";
            if (scanned == 0) return anyUsableScope ? "PARTIAL" : "FAILED";
            return failed > 0 || disabled > 0 ? "PARTIAL" : "SUCCEEDED";
        }
    }

    private record Scope(long runScopeId, long scopeId, String contentType,
                         String approvedRef, String historyLimit, boolean enabled,
                         long connectionVersion, long runVersion,
                         String connectionStatus, String authRef) { }
    private record ScopeResult(boolean usable, boolean complete, String gap) { }
}
