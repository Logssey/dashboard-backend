package com.logssey.secretworker.github;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import org.springframework.jdbc.core.JdbcTemplate;

import com.logssey.secretworker.ClaimedSecretJob;
import com.logssey.secretworker.SecretJobExecutionService;
import com.logssey.secretworker.SecretJobFailure;
import com.logssey.secretworker.SecretJobFailureCode;
import com.logssey.secretworker.SecretJobProcessor;
import com.logssey.secretworker.SecretJobProperties;
import com.logssey.secretworker.detection.SecretFindingRepository;
import com.logssey.secretworker.detector.DetectionFailure;
import com.logssey.secretworker.detector.SecretContentDetector;

/** Processes only approved GitHub scopes; bytes remain in the collector's synchronous callback. */
public final class GitHubSecretJobProcessor implements SecretJobProcessor {
    private final JdbcTemplate jdbc;
    private final GitHubCollector collector;
    private final SecretContentDetector detector;
    private final SecretFindingRepository findings;
    private final SecretJobProperties jobs;

    GitHubSecretJobProcessor(JdbcTemplate jdbc, GitHubCollector collector,
                             SecretContentDetector detector, SecretFindingRepository findings,
                             SecretJobProperties jobs) {
        this.jdbc = jdbc;
        this.collector = collector;
        this.detector = detector;
        this.findings = findings;
        this.jobs = jobs;
    }

    @Override
    public String provider() {
        return "GITHUB";
    }

    @Override
    public void process(ClaimedSecretJob job, SecretJobExecutionService execution) {
        var heartbeat = Executors.newSingleThreadScheduledExecutor(
                Thread.ofVirtual().name("secret-job-lease-heartbeat").factory());
        var leaseLost = new AtomicBoolean();
        long intervalMillis = Math.max(1_000L, jobs.leaseDuration().toMillis() / 3);
        var task = heartbeat.scheduleWithFixedDelay(() -> {
            try {
                if (!execution.renewLease(job.jobId(), job.leaseToken())) leaseLost.set(true);
            } catch (RuntimeException error) {
                leaseLost.set(true);
            }
        }, intervalMillis, intervalMillis, TimeUnit.MILLISECONDS);
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
                SELECT rs.run_scope_id, s.approved_ref, s.history_limit, s.enabled,
                       c.scope_version, r.scope_version AS run_scope_version, c.status
                FROM secret_scan_runs r
                JOIN secret_connections c ON c.connection_id = r.connection_id
                JOIN secret_run_scopes rs ON rs.run_id = r.run_id
                JOIN secret_connection_scopes s ON s.scope_id = rs.scope_id
                    AND s.connection_id = c.connection_id
                WHERE r.run_id = ? AND r.job_id = ? AND r.connection_id = ? AND c.provider = 'GITHUB'
                ORDER BY rs.run_scope_id
                """, (rs, row) -> new Scope(rs.getLong("run_scope_id"), rs.getString("approved_ref"),
                rs.getString("history_limit"), rs.getBoolean("enabled"),
                rs.getLong("scope_version"), rs.getLong("run_scope_version"), rs.getString("status")),
                job.runId(), job.jobId(), job.connectionId());
        if (scopes.isEmpty() || scopes.stream().anyMatch(scope -> !scope.enabled()
                || !"ACTIVE".equals(scope.connectionStatus())
                || scope.connectionVersion() != scope.runVersion())) {
            throw new SecretJobFailure(SecretJobFailureCode.SOURCE_ACCESS_DENIED, false);
        }
        withLease(job, execution, () -> jdbc.update("""
                UPDATE secret_scan_runs SET collection_status = 'RUNNING',
                    detection_status = 'RUNNING', validation_status = 'SKIPPED'
                WHERE run_id = ?
                """, job.runId()));

        int successfulScopes = 0;
        int acceptedObjects = 0;
        int totalGaps = 0;
        String firstFailure = null;
        for (Scope scope : scopes) {
            if (leaseLost.get()) throw new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
            ScopeResult result = processScope(job, scope, execution);
            if (result.usable()) successfulScopes++;
            acceptedObjects += result.objectCount();
            totalGaps += result.gapCount();
            if (firstFailure == null) firstFailure = result.failureCode();
        }
        boolean allSucceeded = successfulScopes == scopes.size() && totalGaps == 0;
        String collectionStatus = successfulScopes == 0 ? "FAILED" : allSucceeded ? "SUCCEEDED" : "PARTIAL";
        String detectionStatus = acceptedObjects == 0 ? allSucceeded ? "SKIPPED" : "FAILED"
                : totalGaps == 0 ? "SUCCEEDED" : "PARTIAL";
        String failureCode = allSucceeded ? null : firstFailure == null ? "COLLECTION_PARTIAL" : firstFailure;
        withLease(job, execution, () -> jdbc.update("""
                UPDATE secret_scan_runs SET collection_status = ?, detection_status = ?, failure_code = ?
                WHERE run_id = ?
                """, collectionStatus, detectionStatus, failureCode, job.runId()));
        if (successfulScopes == 0) {
            throw new SecretJobFailure(retryCode(firstFailure), retryable(firstFailure));
        }
    }

    private ScopeResult processScope(ClaimedSecretJob job, Scope scope,
                                     SecretJobExecutionService execution) {
        GitHubApprovedScope approved;
        try {
            approved = GitHubApprovedScope.fromApprovedRef(scope.approvedRef(), scope.historyLimit());
        } catch (IllegalArgumentException error) {
            finishScope(job, scope.id(), "FAILED", 0, "INVALID_APPROVED_SCOPE", execution);
            return new ScopeResult(false, 0, 1, "INVALID_APPROVED_SCOPE");
        }
        withLease(job, execution, () -> jdbc.update("""
                UPDATE secret_run_scopes SET collection_status = 'RUNNING', started_at = COALESCE(started_at, ?),
                    finished_at = NULL, object_count = NULL, failure_code = NULL
                WHERE run_scope_id = ?
                """, utcNow(), scope.id()));
        AtomicLong toolRunId = new AtomicLong();
        withLease(job, execution, () -> toolRunId.set(findings.beginGitleaksRun(scope.id(),
                detector.engineVersion(), detector.configHash(), Instant.now())));
        AtomicReference<String> consumerFailure = new AtomicReference<>();
        GitHubCollector.Result result = collector.collect(approved, GitHubCollectionLimits.DEFAULT,
                (source, bytes) -> {
                    if (!execution.renewLease(job.jobId(), job.leaseToken())) {
                        consumerFailure.set("LEASE_EXPIRED");
                        throw new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
                    }
                    try {
                        var scan = detector.scan(bytes);
                        withLease(job, execution, () -> findings.recordObject(toolRunId.get(),
                                source.owner() + "/" + source.repository() + "/" + source.path(),
                                source.blobSha(), bytes, scan, Instant.now()));
                    } catch (DetectionFailure error) {
                        consumerFailure.set("DETECTOR_" + error.code().name());
                        throw error;
                    } catch (RuntimeException error) {
                        consumerFailure.compareAndSet(null, "RESULT_PERSISTENCE_FAILED");
                        throw error;
                    }
                });
        String status = result.status().name();
        String code = consumerFailure.get() != null ? consumerFailure.get()
                : result.gaps().isEmpty() ? null : "GITHUB_" + result.gaps().getFirst().code().name();
        withLease(job, execution, () -> findings.finishToolRun(toolRunId.get(), status, code, Instant.now()));
        finishScope(job, scope.id(), status, result.objectCount(), code, execution);
        return new ScopeResult(result.status() == GitHubCollector.Status.SUCCEEDED
                || result.status() == GitHubCollector.Status.PARTIAL && result.objectCount() > 0,
                result.objectCount(), result.gaps().size(), code);
    }

    private void finishScope(ClaimedSecretJob job, long scopeId, String status, int objectCount,
                             String code, SecretJobExecutionService execution) {
        withLease(job, execution, () -> jdbc.update("""
                UPDATE secret_run_scopes SET collection_status = ?, object_count = ?,
                    failure_code = ?, finished_at = ?
                WHERE run_scope_id = ?
                """, status, objectCount, code, utcNow(), scopeId));
    }

    private static void withLease(ClaimedSecretJob job, SecretJobExecutionService execution,
                                  Runnable persistence) {
        if (!execution.persistIfLeased(job.jobId(), job.leaseToken(), persistence)) {
            throw new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
        }
    }

    private static OffsetDateTime utcNow() {
        return Instant.now().atOffset(ZoneOffset.UTC);
    }

    private static SecretJobFailureCode retryCode(String code) {
        if ("GITHUB_ACCESS_DENIED".equals(code) || "INVALID_APPROVED_SCOPE".equals(code)) {
            return SecretJobFailureCode.SOURCE_ACCESS_DENIED;
        }
        if ("GITHUB_RATE_LIMITED".equals(code)) return SecretJobFailureCode.SOURCE_RATE_LIMITED;
        return SecretJobFailureCode.SOURCE_UNAVAILABLE;
    }

    private static boolean retryable(String code) {
        return !"GITHUB_ACCESS_DENIED".equals(code) && !"INVALID_APPROVED_SCOPE".equals(code)
                && !"GITHUB_PATH_NOT_FOUND".equals(code);
    }

    private record Scope(long id, String approvedRef, String historyLimit, boolean enabled,
                         long connectionVersion, long runVersion, String connectionStatus) { }
    private record ScopeResult(boolean usable, int objectCount, int gapCount, String failureCode) { }
}
