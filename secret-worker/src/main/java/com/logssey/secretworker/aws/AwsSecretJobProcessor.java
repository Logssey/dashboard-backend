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

/** IAM metadata inventory only. It never treats a listed ID as a recovered secret. */
public final class AwsSecretJobProcessor implements SecretJobProcessor {
    private final JdbcTemplate jdbc;
    private final AwsIamCollector collector;
    private final AwsIamMetadataRepository metadata;
    private final SecretJobProperties jobs;
    private final String expectedAuthRef;

    public AwsSecretJobProcessor(JdbcTemplate jdbc, AwsIamCollector collector,
                                 AwsIamMetadataRepository metadata, SecretJobProperties jobs,
                                 String profile) {
        this.jdbc = jdbc;
        this.collector = collector;
        this.metadata = metadata;
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
        for (Scope scope : scopes) {
            if (leaseLost.get()) throw new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
            ScopeResult result = processScope(job, scope, execution);
            if (result.usable()) succeeded++;
            if (!result.complete()) allSucceeded = false;
            if (firstGap == null) firstGap = result.gap();
        }
        String collectionStatus = succeeded == 0 ? "FAILED" : allSucceeded ? "SUCCEEDED" : "PARTIAL";
        String safeGap = firstGap;
        boolean complete = allSucceeded;
        withLease(job, execution, () -> jdbc.update("""
                UPDATE secret_scan_runs SET collection_status = ?, failure_code = ?
                WHERE run_id = ?
                """, collectionStatus, complete ? null : safeGap, job.runId()));
        if (succeeded == 0) {
            throw new SecretJobFailure(retryCode(firstGap), retryable(firstGap));
        }
    }

    private ScopeResult processScope(ClaimedSecretJob job, Scope scope,
                                     SecretJobExecutionService execution) {
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
        if ("AWS_RATE_LIMITED".equals(gap)) return SecretJobFailureCode.SOURCE_RATE_LIMITED;
        if ("AWS_UNAVAILABLE".equals(gap)) return SecretJobFailureCode.SOURCE_UNAVAILABLE;
        return SecretJobFailureCode.SOURCE_ACCESS_DENIED;
    }

    private static boolean retryable(String gap) {
        return "AWS_RATE_LIMITED".equals(gap) || "AWS_UNAVAILABLE".equals(gap);
    }

    private record Scope(long runScopeId, long scopeId, String contentType,
                         String approvedRef, String historyLimit, boolean enabled,
                         long connectionVersion, long runVersion,
                         String connectionStatus, String authRef) { }
    private record ScopeResult(boolean usable, boolean complete, String gap) { }
}
