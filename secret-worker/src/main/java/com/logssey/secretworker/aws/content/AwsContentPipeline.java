package com.logssey.secretworker.aws.content;

import static com.logssey.secret.run.progress.core.ScanExecutionObserver.*;

import com.logssey.secretworker.ClaimedSecretJob;
import com.logssey.secretworker.SecretJobExecutionService;
import com.logssey.secretworker.SecretJobFailure;
import com.logssey.secretworker.SecretJobFailureCode;
import com.logssey.secretworker.detection.SecretFindingNormalizer;
import com.logssey.secretworker.detection.SecretFindingRepository;
import com.logssey.secretworker.detector.DetectionFailure;
import com.logssey.secretworker.detector.SecretContentDetector;
import com.logssey.secretworker.validation.AwsValidationResult;
import com.logssey.secretworker.validation.AwsValidationService;
import com.logssey.secretworker.validation.SecretValidationAttemptRepository;

import java.time.Instant;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/** Detects and records one exact AWS value while the collector still owns its content buffer. */
public final class AwsContentPipeline {
    private final AwsContentCollector collector;
    private final SecretContentDetector detector;
    private final SecretFindingNormalizer normalizer;
    private final SecretFindingRepository findings;
    private final AwsValidationService validator;
    private final SecretValidationAttemptRepository attempts;
    private final com.logssey.secretworker.validation.GitHubPatValidator githubValidator;
    private final com.logssey.secretworker.validation.NotionTokenValidator notionValidator;

    public AwsContentPipeline(AwsContentCollector collector, SecretContentDetector detector,
                              SecretFindingNormalizer normalizer, SecretFindingRepository findings,
                              AwsValidationService validator, SecretValidationAttemptRepository attempts) {
        this(
                collector,
                detector,
                normalizer,
                findings,
                validator,
                attempts,
                new com.logssey.secretworker.validation.GitHubPatValidator(false));
    }

    public AwsContentPipeline(
            AwsContentCollector collector,
            SecretContentDetector detector,
            SecretFindingNormalizer normalizer,
            SecretFindingRepository findings,
            AwsValidationService validator,
            SecretValidationAttemptRepository attempts,
            com.logssey.secretworker.validation.GitHubPatValidator githubValidator) {
        this(collector, detector, normalizer, findings, validator, attempts, githubValidator,
                new com.logssey.secretworker.validation.NotionTokenValidator(false));
    }

    public AwsContentPipeline(
            AwsContentCollector collector,
            SecretContentDetector detector,
            SecretFindingNormalizer normalizer,
            SecretFindingRepository findings,
            AwsValidationService validator,
            SecretValidationAttemptRepository attempts,
            com.logssey.secretworker.validation.GitHubPatValidator githubValidator,
            com.logssey.secretworker.validation.NotionTokenValidator notionValidator) {
        this.githubValidator = githubValidator;
        this.notionValidator = notionValidator;
        this.collector = collector;
        this.detector = detector;
        this.normalizer = normalizer;
        this.findings = findings;
        this.validator = validator;
        this.attempts = attempts;
    }

    public record Result(AwsContentCollector.Status status, int objectCount, String gapCode) {}

    public boolean isValidationJob(ClaimedSecretJob job) {
        return attempts.isManual(job);
    }

    public boolean hasRetryableValidation(ClaimedSecretJob job) {
        return attempts.hasRetryable(job);
    }

    public String fingerprintKeyVersion() {
        return normalizer.keyVersion();
    }

    public void processValidation(
            ClaimedSecretJob job,
            SecretJobExecutionService execution,
            java.util.function.Predicate<AwsContentScope> accountAllowed) {
        new com.logssey.secretworker.validation.CredentialRevalidationProcessor(
                        attempts.jdbcTemplate(),
                        normalizer,
                        detector,
                        attempts,
                        validator,
                        githubValidator,
                        notionValidator)
                .process(
                        job,
                        execution,
                        (target, sink) -> {
                            var approved =
                                    AwsContentScope.fromApprovedRef(
                                            (String) target.get("content_type"),
                                            (String) target.get("approved_ref"),
                                            (String) target.get("history_limit"));
                            if (!accountAllowed.test(approved)) return false;
                            String ref = "aws-content-scope:" + target.get("scope_id");
                            if (!ref.equals(target.get("source_object_ref"))) return false;
                            return collector
                                            .collect(
                                                    approved,
                                                    true,
                                                    AwsContentCollector.DEFAULT_MAX_BYTES,
                                                    (source, bytes) ->
                                                            sink.accept(ref, null, bytes))
                                            .status()
                                    == AwsContentCollector.Status.SUCCEEDED;
                        });
    }

    /** Kept for one run only. The set contains keyed digests, never raw credentials. */
    public static final class RunValidation {
        private final Set<String> encountered = new HashSet<>();
        private int checked;
        private int inconclusive;
        private int failed;

        boolean firstEncounter(SecretFindingNormalizer.Credential credential) {
            byte[] digest = "CONFIRMED".equals(credential.componentState())
                    ? credential.fingerprint() : credential.candidateLocator();
            String identity = credential.issuer() + ":" + credential.credentialType() + ":"
                    + credential.componentState() + ":" + credential.fingerprintKeyVersion() + ":"
                    + HexFormat.of().formatHex(digest);
            return encountered.add(identity);
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

        void record(com.logssey.secretworker.validation.CredentialValidationResult result) {
            if (Set.of("VALID", "INVALID").contains(result.result())) checked++;
            else if (!("UNCHECKED".equals(result.result())
                    && Set.of("DISABLED", "SYNTHETIC_FIXTURE", "SOURCE_GUARD_BLOCKED")
                            .contains(result.reasonCode()))) inconclusive++;
        }

        void failed() { failed++; }

        public int failureCount() { return failed; }

        public String status() {
            if (failed > 0 || inconclusive > 0) return "PARTIAL";
            return checked > 0 ? "SUCCEEDED" : "SKIPPED";
        }

        public String failureCode() {
            return failed > 0 ? "VALIDATION_ATTEMPT_FAILED" : "VALIDATION_INCONCLUSIVE";
        }
    }

    public Result process(ClaimedSecretJob job, SecretJobExecutionService execution,
                          long scopeId, long runScopeId, AwsContentScope approved,
                          RunValidation validation) {
        String sourceRef = "aws-content-scope:" + scopeId;
        AtomicLong toolRunId = new AtomicLong();
        withLease(job, execution, () -> toolRunId.set(findings.beginGitleaksRun(runScopeId,
                detector.engineVersion(), detector.configHash(), Instant.now())));
        AtomicReference<String> consumerGap = new AtomicReference<>();
        AwsContentCollector.Result result =
                collector.observed(execution.observer(job, runScopeId)).collect(
                        approved,
                        true,
                        AwsContentCollector.DEFAULT_MAX_BYTES,
                        (source, bytes) -> {
                            if (!execution.renewLease(job.jobId(), job.leaseToken())) {
                                consumerGap.set("LEASE_EXPIRED");
                                throw new SecretJobFailure(
                                        SecretJobFailureCode.LEASE_EXPIRED, true);
                            }
                            try {
                                var scan = execution.observer(job, runScopeId).measure(
                                    Stage.DETECTION, Operation.GITLEAKS_SCAN, () -> detector.scan(bytes));
                                var inspection =
                                        execution.observer(job, runScopeId).measure(
                                    Stage.DETECTION, Operation.CANDIDATE_NORMALIZATION, () -> normalizer.inspect(
                                                job.connectionId(),
                                                sourceRef,
                                                bytes,
                                                scan.findings()));
                                if (unprovenRecheckAbsence(job, inspection)) {
                                    consumerGap.set("DETECTOR_NORMALIZATION_INCOMPLETE");
                                    throw new IllegalStateException("DETECTOR_NORMALIZATION_INCOMPLETE");
                                }
                                withLease(
                                        job,
                                        execution,
                                        () ->
                                                findings.recordInspection(
                                                        toolRunId.get(),
                                                        sourceRef,
                                                        null,
                                                        inspection,
                                                        scan,
                                                        Instant.now(), execution.observer(job, runScopeId)));
                                for (var candidate : inspection.awsCandidates()) {
                                    if (!validation.firstEncounter(candidate.credential()))
                                        continue;
                                    try {
                                        AwsValidationResult checked =
                                                attempts.validateAws(
                                                        job,
                                                        candidate.credential(),
                                                        candidate.material(),
                                                        false,
                                                        validator,
                                                        runScopeId,
                                                        sourceRef,
                                                        null);
                                        validation.record(checked);
                                    } catch (SecretJobFailure error) {
                                        throw error;
                                    } catch (RuntimeException error) {
                                        // Provider and DB messages may contain raw credential
                                        // material.
                                        validation.failed();
                                    }
                                }
                                for (var candidate : inspection.githubCandidates()) {
                                    if (!validation.firstEncounter(candidate.credential()))
                                        continue;
                                    try {
                                        validation.record(
                                                attempts.validateGitHub(
                                                        job,
                                                        candidate,
                                                        githubValidator,
                                                        runScopeId,
                                                        sourceRef,
                                                        null));
                                    } catch (SecretJobFailure error) {
                                        throw error;
                                    } catch (RuntimeException ignored) {
                                        validation.failed();
                                    }
                                }
                                for (var candidate : inspection.notionCandidates()) {
                                    if (!validation.firstEncounter(candidate.credential())) continue;
                                    try {
                                        validation.record(attempts.validateNotion(
                                                job, candidate, notionValidator, runScopeId, sourceRef, null));
                                    } catch (SecretJobFailure error) {
                                        throw error;
                                    } catch (RuntimeException ignored) {
                                        validation.failed();
                                    }
                                }
                                for (var credential : inspection.credentials()) {
                                    if (Set.of("AWS", "GITHUB", "NOTION").contains(credential.issuer()))
                                        continue;
                                    if (!validation.firstEncounter(credential)) continue;
                                    validation.record(
                                            attempts.recordUnsupported(
                                                    job, credential, runScopeId));
                                }
                            } catch (DetectionFailure error) {
                                consumerGap.set("DETECTOR_" + error.code().name());
                                throw error;
                            } catch (SecretJobFailure error) {
                                consumerGap.set("LEASE_EXPIRED");
                                throw error;
                            } catch (RuntimeException error) {
                                consumerGap.compareAndSet(null, "RESULT_PERSISTENCE_FAILED");
                                throw error;
                            }
                        });
        String gap = consumerGap.get() != null ? consumerGap.get()
                : result.gaps().isEmpty() ? null : "AWS_CONTENT_" + result.gaps().getFirst().name();
        withLease(job, execution, () -> findings.finishToolRun(toolRunId.get(),
                result.status().name(), gap, Instant.now()));
        return new Result(result.status(), result.objectCount(), gap);
    }

    private boolean unprovenRecheckAbsence(ClaimedSecretJob job,
                                           SecretFindingNormalizer.Inspection inspection) {
        var normalized = inspection.credentials().stream()
                .flatMap(credential -> credential.findings().stream())
                .collect(java.util.stream.Collectors.toSet());
        if (normalized.containsAll(inspection.detectorFindings())
                && inspection.credentials().stream().allMatch(c -> "CONFIRMED".equals(c.componentState())))
            return false;
        var targets = attempts.jdbcTemplate().queryForList("""
                SELECT v.baseline_identity,v.baseline_fingerprint_version,o.location_key
                FROM secret_case_revalidations v JOIN secret_occurrences o USING(occurrence_id)
                JOIN secret_jobs j ON j.job_id=v.job_id AND j.purpose='LOCATION_RECHECK'
                WHERE v.job_id=? AND v.status='PENDING'
                """, job.jobId());
        if (targets.isEmpty()) return false;
        var target = targets.getFirst();
        // A positive, identity-matched observation is still useful. Uninterpreted candidates
        // must not otherwise turn a changed/unsupported representation into proof of removal.
        return inspection.credentials().stream().noneMatch(credential ->
                "CONFIRMED".equals(credential.componentState())
                        && credential.locationKey().equals(target.get("location_key"))
                        && credential.fingerprintKeyVersion().equals(target.get("baseline_fingerprint_version"))
                        && java.security.MessageDigest.isEqual(credential.fingerprint(),
                                (byte[]) target.get("baseline_identity")));
    }

    private static void withLease(ClaimedSecretJob job, SecretJobExecutionService execution,
                                  Runnable persistence) {
        if (!execution.persistIfLeased(job.jobId(), job.leaseToken(), persistence)) {
            throw new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
        }
    }
}
