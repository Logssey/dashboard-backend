package com.logssey.secretworker.notion;

import com.logssey.secretworker.ClaimedSecretJob;
import com.logssey.secretworker.SecretJobExecutionService;
import com.logssey.secretworker.SecretJobFailure;
import com.logssey.secretworker.SecretJobFailureCode;
import com.logssey.secretworker.SecretJobProcessor;
import com.logssey.secretworker.SecretJobProperties;
import com.logssey.secretworker.detection.SecretFindingNormalizer;
import com.logssey.secretworker.detection.SecretFindingRepository;
import com.logssey.secretworker.detector.DetectionFailure;
import com.logssey.secretworker.detector.SecretContentDetector;
import com.logssey.secretworker.validation.AwsValidationResult;
import com.logssey.secretworker.validation.AwsValidationService;
import com.logssey.secretworker.validation.CredentialValidationResult;
import com.logssey.secretworker.validation.GitHubPatValidator;
import com.logssey.secretworker.validation.NotionTokenValidator;
import com.logssey.secretworker.validation.SecretValidationAttemptRepository;
import org.springframework.jdbc.core.JdbcTemplate;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Processes only approved Notion page scopes. Same contract as the GitHub processor: page text stays
 * in worker memory, goes to Gitleaks over stdin, and only HMAC identities, masked labels, locations
 * and rule metadata are stored. Validation calls happen outside DB transactions.
 */
public final class NotionSecretJobProcessor implements SecretJobProcessor {
    private final JdbcTemplate jdbc;
    private final NotionPageClient client;
    private final SecretContentDetector detector;
    private final SecretFindingRepository findings;
    private final SecretFindingNormalizer normalizer;
    private final AwsValidationService awsValidator;
    private final SecretValidationAttemptRepository attempts;
    private final SecretJobProperties jobs;
    private final GitHubPatValidator githubValidator;
    private final NotionTokenValidator notionValidator;
    private final List<NotionPageAccessSink> accessSinks;

    public NotionSecretJobProcessor(
            JdbcTemplate jdbc,
            NotionPageClient client,
            SecretContentDetector detector,
            SecretFindingRepository findings,
            SecretFindingNormalizer normalizer,
            AwsValidationService awsValidator,
            SecretValidationAttemptRepository attempts,
            SecretJobProperties jobs,
            GitHubPatValidator githubValidator,
            NotionTokenValidator notionValidator,
            List<NotionPageAccessSink> accessSinks) {
        this.jdbc = jdbc;
        this.client = client;
        this.detector = detector;
        this.findings = findings;
        this.normalizer = normalizer;
        this.awsValidator = awsValidator;
        this.attempts = attempts;
        this.jobs = jobs;
        this.githubValidator = githubValidator;
        this.notionValidator = notionValidator;
        this.accessSinks = List.copyOf(accessSinks);
    }

    @Override
    public String provider() {
        return "NOTION";
    }

    @Override
    public void process(ClaimedSecretJob job, SecretJobExecutionService execution) {
        if (attempts.isManual(job)) {
            // Manual credential revalidation re-reads the source; it is not registered for Notion yet.
            attempts.recordManualBlocked(job, "UNSUPPORTED_SOURCE");
            return;
        }
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
        List<Scope> scopes = jdbc.query(
                """
SELECT rs.run_scope_id, s.approved_ref, s.history_limit, s.enabled,
       c.scope_version, r.scope_version AS run_scope_version, c.status, s.revision, rs.scope_revision AS captured_revision
FROM secret_scan_runs r
JOIN secret_connections c ON c.connection_id = r.connection_id
JOIN secret_run_scopes rs ON rs.run_id = r.run_id
JOIN secret_connection_scopes s ON s.scope_id = rs.scope_id
    AND s.connection_id = c.connection_id
WHERE r.run_id = ? AND r.job_id = ? AND r.connection_id = ? AND c.provider = 'NOTION'
ORDER BY rs.run_scope_id
""",
                (rs, row) -> new Scope(
                        rs.getLong("run_scope_id"),
                        rs.getString("approved_ref"),
                        rs.getString("history_limit"),
                        rs.getBoolean("enabled"),
                        rs.getLong("scope_version"),
                        rs.getLong("run_scope_version"),
                        rs.getString("status"),
                        rs.getLong("revision"),
                        rs.getObject("captured_revision", Long.class)),
                job.runId(), job.jobId(), job.connectionId());
        if (scopes.isEmpty() || scopes.stream().anyMatch(scope -> !scope.enabled()
                || !"ACTIVE".equals(scope.connectionStatus())
                || scope.connectionVersion() != scope.runVersion()
                || !Objects.equals(scope.capturedRevision(), scope.revision()))) {
            throw new SecretJobFailure(SecretJobFailureCode.SOURCE_ACCESS_DENIED, false);
        }
        withLease(job, execution, () -> jdbc.update(
                """
                UPDATE secret_scan_runs SET collection_status = 'RUNNING',
                    detection_status = 'RUNNING', validation_status = 'RUNNING'
                WHERE run_id = ?
                """, job.runId()));

        ValidationProgress validation = new ValidationProgress();
        int successfulScopes = 0;
        int acceptedObjects = 0;
        int totalGaps = 0;
        String firstFailure = null;
        for (Scope scope : scopes) {
            if (leaseLost.get()) throw new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
            int failuresBefore = validation.failed;
            ScopeResult result = processScope(job, scope, execution, validation);
            if (!execution.recordScopeEvidence(job.jobId(), job.leaseToken(), scope.id(),
                    validation.failed > failuresBefore)) {
                throw new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
            }
            if (result.usable()) successfulScopes++;
            acceptedObjects += result.objectCount();
            totalGaps += result.gapCount();
            if (firstFailure == null) firstFailure = result.failureCode();
        }
        boolean allSucceeded = successfulScopes == scopes.size() && totalGaps == 0;
        String collectionStatus = successfulScopes == 0 ? "FAILED" : allSucceeded ? "SUCCEEDED" : "PARTIAL";
        String detectionStatus = acceptedObjects == 0 ? allSucceeded ? "SKIPPED" : "FAILED"
                : totalGaps == 0 ? "SUCCEEDED" : "PARTIAL";
        String validationStatus = validation.status();
        String failureCode = !allSucceeded
                ? firstFailure == null ? "COLLECTION_PARTIAL" : firstFailure
                : "PARTIAL".equals(validationStatus) ? validation.failureCode() : null;
        withLease(job, execution, () -> jdbc.update(
                """
UPDATE secret_scan_runs SET collection_status = ?, detection_status = ?,
    validation_status = ?, failure_code = ?
WHERE run_id = ?
""", collectionStatus, detectionStatus, validationStatus, failureCode, job.runId()));
        if (successfulScopes == 0) {
            throw new SecretJobFailure(retryCode(firstFailure), retryable(firstFailure));
        }
        if (attempts.hasRetryable(job))
            throw new SecretJobFailure(SecretJobFailureCode.VALIDATOR_TEMPORARY, true);
    }

    private ScopeResult processScope(ClaimedSecretJob job, Scope scope,
                                     SecretJobExecutionService execution, ValidationProgress validation) {
        NotionApprovedScope approved;
        try {
            approved = NotionApprovedScope.fromApprovedRef(scope.approvedRef(), scope.historyLimit());
        } catch (IllegalArgumentException error) {
            finishScope(job, scope.id(), "FAILED", 0, "INVALID_APPROVED_SCOPE", execution);
            return new ScopeResult(false, 0, 1, "INVALID_APPROVED_SCOPE");
        }
        withLease(job, execution, () -> jdbc.update(
                """
UPDATE secret_run_scopes SET collection_status = 'RUNNING', started_at = COALESCE(started_at, ?),
    finished_at = NULL, object_count = NULL, failure_code = NULL
WHERE run_scope_id = ?
""", utcNow(), scope.id()));
        AtomicLong toolRunId = new AtomicLong();
        withLease(job, execution, () -> toolRunId.set(findings.beginGitleaksRun(scope.id(),
                detector.engineVersion(), detector.configHash(), Instant.now())));

        String status;
        String code = null;
        int objects = 0;
        boolean unattributed = false;
        NotionPageClient.PageMetadata metadata = null;
        try {
            metadata = client.metadata(approved);
            if (metadata.inTrash()) {
                status = "FAILED";
                code = "NOTION_PAGE_TRASHED";
            } else {
                NotionPageClient.PageMarkdown page = client.markdown(approved);
                byte[] bytes = page.utf8();
                try {
                    if (!execution.renewLease(job.jobId(), job.leaseToken())) {
                        throw new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
                    }
                    unattributed = inspect(job, execution, scope, approved, metadata, bytes,
                            toolRunId.get(), validation);
                } finally {
                    Arrays.fill(bytes, (byte) 0);
                }
                objects = 1;
                // A detector hit that the shared normalizer cannot attribute (e.g. a token written in
                // Korean prose or a table) must not look like a clean, empty page.
                status = page.truncated() || unattributed ? "PARTIAL" : "SUCCEEDED";
                code = page.truncated() ? "NOTION_CONTENT_TRUNCATED"
                        : unattributed ? "NOTION_UNATTRIBUTED_FINDINGS" : null;
            }
        } catch (NotionSourceException error) {
            status = "FAILED";
            code = "NOTION_" + error.code().name();
        } catch (DetectionFailure error) {
            status = "FAILED";
            code = "DETECTOR_" + error.code().name();
        } catch (SecretJobFailure error) {
            throw error;
        } catch (RuntimeException error) {
            // Exception text may contain source material; only a fixed code is kept.
            status = "FAILED";
            code = "RESULT_PERSISTENCE_FAILED";
        }
        String finalStatus = status;
        String finalCode = code;
        int finalObjects = objects;
        withLease(job, execution, () -> findings.finishToolRun(toolRunId.get(), finalStatus, finalCode, Instant.now()));
        NotionPageClient.PageMetadata observed = metadata;
        withLease(job, execution, () -> {
            jdbc.update("UPDATE secret_run_scopes SET collection_status=?,object_count=?,failure_code=?,finished_at=?"
                            + " WHERE run_scope_id=?",
                    finalStatus, finalObjects, finalCode, utcNow(), scope.id());
            if ("SUCCEEDED".equals(finalStatus) && observed != null && !accessSinks.isEmpty()) {
                List<Long> occurrenceIds = jdbc.queryForList(
                        "SELECT DISTINCT f.occurrence_id FROM secret_findings f"
                                + " JOIN secret_tool_runs t USING(tool_run_id) WHERE"
                                + " t.run_scope_id=? AND f.occurrence_id IS NOT NULL"
                                + " ORDER BY f.occurrence_id",
                        Long.class, scope.id());
                var observation = new NotionPageAccessObservation(scope.id(), occurrenceIds,
                        observed.publishedToWeb(), utcNow(),
                        observed.publishedToWeb() ? "PUBLISHED_TO_WEB" : "NOT_PUBLISHED");
                for (var sink : accessSinks) sink.observe(observation);
            }
        });
        boolean usable = "SUCCEEDED".equals(finalStatus) || "PARTIAL".equals(finalStatus) && finalObjects > 0;
        return new ScopeResult(usable, finalObjects, "SUCCEEDED".equals(finalStatus) ? 0 : 1, finalCode);
    }

    /** @return true when the detector reported positions that no stored credential accounts for. */
    private boolean inspect(ClaimedSecretJob job, SecretJobExecutionService execution, Scope scope,
                         NotionApprovedScope approved, NotionPageClient.PageMetadata metadata,
                         byte[] bytes, long toolRunId, ValidationProgress validation) {
        var scan = detector.scan(bytes);
        String sourceRef = approved.sourceObjectRef();
        var inspection = normalizer.inspect(job.connectionId(), sourceRef, bytes, scan.findings());
        withLease(job, execution, () -> findings.recordInspection(
                toolRunId, sourceRef, metadata.lastEditedTime(), inspection, scan, Instant.now()));
        for (var candidate : inspection.awsCandidates()) {
            if (!validation.firstEncounter(candidate.credential())) continue;
            try {
                validation.record(attempts.validateAws(job, candidate.credential(), candidate.material(),
                        false, awsValidator, scope.id(), sourceRef, metadata.lastEditedTime()));
            } catch (SecretJobFailure error) {
                throw error;
            } catch (RuntimeException error) {
                validation.failed();
            }
        }
        for (var candidate : inspection.notionCandidates()) {
            if (!validation.firstEncounter(candidate.credential())) continue;
            try {
                validation.record(attempts.validateNotion(job, candidate, notionValidator,
                        scope.id(), sourceRef, metadata.lastEditedTime()));
            } catch (SecretJobFailure error) {
                throw error;
            } catch (RuntimeException error) {
                validation.failed();
            }
        }
        for (var candidate : inspection.githubCandidates()) {
            if (!validation.firstEncounter(candidate.credential())) continue;
            try {
                validation.record(attempts.validateGitHub(job, candidate, githubValidator,
                        scope.id(), sourceRef, metadata.lastEditedTime()));
            } catch (SecretJobFailure error) {
                throw error;
            } catch (RuntimeException error) {
                validation.failed();
            }
        }
        for (var credential : inspection.credentials()) {
            if (Set.of("AWS", "GITHUB", "NOTION").contains(credential.issuer())) continue;
            if (!validation.firstEncounter(credential)) continue;
            validation.record(attempts.recordUnsupported(job, credential, scope.id()));
        }
        Set<com.logssey.secretworker.detector.GitleaksFinding> attributed = new HashSet<>();
        for (var credential : inspection.credentials()) attributed.addAll(credential.findings());
        return !attributed.containsAll(new HashSet<>(scan.findings()));
    }

    private void finishScope(ClaimedSecretJob job, long scopeId, String status, int objectCount,
                             String code, SecretJobExecutionService execution) {
        withLease(job, execution, () -> jdbc.update(
                """
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

    /** Same counting rules as the GitHub processor, without the GitHub fixture exemption. */
    private static final class ValidationProgress {
        private final Set<String> encountered = new HashSet<>();
        private int checked;
        private int inconclusive;
        private int failed;

        boolean firstEncounter(SecretFindingNormalizer.Credential credential) {
            byte[] digest = "CONFIRMED".equals(credential.componentState())
                    ? credential.fingerprint() : credential.candidateLocator();
            return encountered.add(credential.issuer() + ":" + credential.credentialType() + ":"
                    + credential.componentState() + ":" + credential.fingerprintKeyVersion() + ":"
                    + HexFormat.of().formatHex(digest));
        }

        void record(AwsValidationResult result) {
            if (result.status() == AwsValidationResult.Status.UNCHECKED) {
                if (result.reason() != AwsValidationResult.Reason.DISABLED
                        && result.reason() != AwsValidationResult.Reason.SYNTHETIC_FIXTURE
                        && result.reason() != AwsValidationResult.Reason.SOURCE_GUARD_BLOCKED)
                    inconclusive++;
            } else if (result.status() == AwsValidationResult.Status.UNKNOWN) {
                inconclusive++;
            } else {
                checked++;
            }
        }

        void record(CredentialValidationResult result) {
            if (Set.of("VALID", "INVALID").contains(result.result())) checked++;
            else if (!("UNCHECKED".equals(result.result())
                    && Set.of("DISABLED", "SYNTHETIC_FIXTURE", "SOURCE_GUARD_BLOCKED", "UNSUPPORTED_TYPE")
                            .contains(result.reasonCode()))) inconclusive++;
        }

        void failed() { failed++; }

        String status() {
            if (failed > 0 || inconclusive > 0) return "PARTIAL";
            return checked > 0 ? "SUCCEEDED" : "SKIPPED";
        }

        String failureCode() {
            return failed > 0 ? "VALIDATION_ATTEMPT_FAILED" : "VALIDATION_INCONCLUSIVE";
        }
    }

    private static SecretJobFailureCode retryCode(String code) {
        if ("NOTION_ACCESS_DENIED".equals(code) || "NOTION_TOKEN_UNAVAILABLE".equals(code)
                || "INVALID_APPROVED_SCOPE".equals(code)) {
            return SecretJobFailureCode.SOURCE_ACCESS_DENIED;
        }
        if ("NOTION_RATE_LIMITED".equals(code)) return SecretJobFailureCode.SOURCE_RATE_LIMITED;
        if (code != null && code.startsWith("DETECTOR_")) return SecretJobFailureCode.DETECTOR_TEMPORARY;
        return SecretJobFailureCode.SOURCE_UNAVAILABLE;
    }

    private static boolean retryable(String code) {
        return !Set.of("NOTION_ACCESS_DENIED", "NOTION_TOKEN_UNAVAILABLE", "INVALID_APPROVED_SCOPE",
                "NOTION_NOT_FOUND", "NOTION_PAGE_TRASHED").contains(code);
    }

    private record Scope(long id, String approvedRef, String historyLimit, boolean enabled,
                         long connectionVersion, long runVersion, String connectionStatus,
                         long revision, Long capturedRevision) { }
    private record ScopeResult(boolean usable, int objectCount, int gapCount, String failureCode) { }
}
