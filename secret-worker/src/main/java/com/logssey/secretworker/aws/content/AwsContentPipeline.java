package com.logssey.secretworker.aws.content;

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

    public AwsContentPipeline(AwsContentCollector collector, SecretContentDetector detector,
                              SecretFindingNormalizer normalizer, SecretFindingRepository findings,
                              AwsValidationService validator, SecretValidationAttemptRepository attempts) {
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

    public void processValidation(
            ClaimedSecretJob job,
            SecretJobExecutionService execution,
            java.util.function.Predicate<AwsContentScope> accountAllowed) {
        attempts.processor(normalizer, detector, validator)
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
                        }); }

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
                        && result.reason() != AwsValidationResult.Reason.SOURCE_GUARD_BLOCKED) inconclusive++;
            } else if (result.status() == AwsValidationResult.Status.UNKNOWN) {
                inconclusive++;
            } else {
                checked++;
            }
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
        AwsContentCollector.Result result = collector.collect(approved, true,
                AwsContentCollector.DEFAULT_MAX_BYTES, (source, bytes) -> {
                    if (!execution.renewLease(job.jobId(), job.leaseToken())) {
                        consumerGap.set("LEASE_EXPIRED");
                        throw new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
                    }
                    try {
                        var scan = detector.scan(bytes);
                        var inspection = normalizer.inspect(job.connectionId(), sourceRef,
                                bytes, scan.findings());
                        withLease(job, execution, () -> findings.recordInspection(toolRunId.get(),
                                sourceRef, null, inspection, scan, Instant.now()));
                        for (var candidate : inspection.awsCandidates()) {
                            if (!validation.firstEncounter(candidate.credential())) continue;
                            try {
                                AwsValidationResult checked = attempts.validateAws(job,
                                        candidate.credential(),candidate.material(),false,validator,runScopeId);
                                validation.record(checked);
                            } catch (SecretJobFailure error) {
                                throw error;
                            } catch (RuntimeException error) {
                                        // Provider and DB messages may contain raw credential
                                        // material.
                                validation.failed();
                            }
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

    private static void withLease(ClaimedSecretJob job, SecretJobExecutionService execution,
                                  Runnable persistence) {
        if (!execution.persistIfLeased(job.jobId(), job.leaseToken(), persistence)) {
            throw new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
        }
    }
}
