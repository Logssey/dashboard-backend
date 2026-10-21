package com.logssey.secretworker.validation;

import com.logssey.secretworker.*;
import com.logssey.secretworker.detection.SecretFindingNormalizer;
import com.logssey.secretworker.detector.SecretContentDetector;

import org.springframework.jdbc.core.JdbcTemplate;

import java.util.*;
import java.util.concurrent.atomic.*;

/** Single-location source reacquisition. Does not mutate occurrences, cases or presence. */
public final class CredentialRevalidationProcessor {
    @FunctionalInterface
    public interface ContentSink {
        void accept(String sourceRef, String version, byte[] bytes);
    }

    @FunctionalInterface
    public interface SourceReader {
        boolean read(Map<String, Object> target, ContentSink sink);
    }

    private final JdbcTemplate jdbc;
    private final SecretFindingNormalizer normalizer;
    private final SecretContentDetector detector;
    private final SecretValidationAttemptRepository attempts;
    private final AwsValidationService aws;

    public CredentialRevalidationProcessor(
            JdbcTemplate jdbc,
            SecretFindingNormalizer normalizer,
            SecretContentDetector detector,
            SecretValidationAttemptRepository attempts,
            AwsValidationService aws) {
        this.jdbc = jdbc;
        this.normalizer = normalizer;
        this.detector = detector;
        this.attempts = attempts;
        this.aws = aws;
    }

    public void process(
            ClaimedSecretJob job, SecretJobExecutionService execution, SourceReader reader) {
        var target = attempts.manualTarget(job);
        if (target == null)
            throw new SecretJobFailure(SecretJobFailureCode.SOURCE_ACCESS_DENIED, false);
        String blocked =
                !attempts.targetCurrent(target)
                        ? "APPROVAL_CHANGED"
                        : attempts.manualBlockReason(
                                job, target, "AWS".equals(target.get("issuer")) && aws.enabled());
        if (blocked != null) {
            attempts.recordManualBlocked(job, blocked);
            finish(job, execution, false, CredentialValidationResult.unchecked(blocked));
            return;
        }
        var prepared = attempts.prepareManual(job, target);
        if (prepared != null) {
            finish(job, execution, false, prepared);
            return;
        }
        var outcome = new AtomicReference<CredentialValidationResult>();
        var consumed = new AtomicBoolean();
        boolean fetched;
        try {
            fetched =
                    reader.read(
                            target,
                            (source, version, bytes) -> {
                                if (!execution.renewLease(job.jobId(), job.leaseToken()))
                                    throw new SecretJobFailure(
                                            SecretJobFailureCode.LEASE_EXPIRED, true);
                                var current = attempts.manualTarget(job);
                                if (!attempts.targetCurrent(current)) {
                                    attempts.recordManualBlocked(job, "APPROVAL_CHANGED");
                                    outcome.set(
                                            CredentialValidationResult.unchecked(
                                                    "APPROVAL_CHANGED"));
                                    return;
                                }
                                consumed.set(true);
                                var scan = detector.scan(bytes);
                                var inspected =
                                        normalizer.inspect(
                                                job.connectionId(), source, bytes, scan.findings());
                                for (var candidate : inspected.awsCandidates())
                                    if (attempts.matchesTarget(target, candidate.credential())) {
                                        var checked =
                                                attempts.validateAws(
                                                        job,
                                                        candidate.credential(),
                                                        candidate.material(),
                                                        false,
                                                        aws);
                                        outcome.set(
                                                new CredentialValidationResult(
                                                        checked.status().name(),
                                                        checked.reason().name(),
                                                        checked.checkedAt(),
                                                        null,
                                                        null));
                                        break;
                                    }
                            });
        } catch (SecretJobFailure e) {
            throw e;
        } catch (RuntimeException ignored) {
            if (ignored instanceof IllegalStateException
                    && ignored.getMessage() != null
                    && ignored.getMessage().startsWith("VALIDATION_PERSISTENCE_FAILED"))
                throw ignored;
            fetched = false;
        }
        if (outcome.get() == null) {
            String reason =
                    fetched && consumed.get() ? "CREDENTIAL_MISMATCH" : "SOURCE_UNAVAILABLE";
            attempts.recordSourceFailure(job, reason);
            outcome.set(CredentialValidationResult.unknown(reason));
        }
        finish(job, execution, fetched, outcome.get());
        if (outcome.get().retryable())
            throw new SecretJobFailure(SecretJobFailureCode.VALIDATOR_TEMPORARY, true);
    }

    private void finish(
            ClaimedSecretJob job,
            SecretJobExecutionService execution,
            boolean fetched,
            CredentialValidationResult result) {
        String collection = fetched ? "SUCCEEDED" : "SKIPPED",
                validation =
                        Set.of("VALID", "INVALID").contains(result.result())
                                ? "SUCCEEDED"
                                : "UNKNOWN".equals(result.result()) ? "PARTIAL" : "SKIPPED";
        if (!execution.persistIfLeased(
                job.jobId(),
                job.leaseToken(),
                () -> {
                    jdbc.update(
                            "UPDATE secret_scan_runs SET"
                                + " collection_status=?,detection_status=?,validation_status=?,failure_code=?"
                                + " WHERE run_id=?",
                            collection,
                            fetched ? "SUCCEEDED" : "SKIPPED",
                            validation,
                            "PARTIAL".equals(validation) ? result.reasonCode() : null,
                            job.runId());
                    jdbc.update(
                            "UPDATE secret_run_scopes SET"
                                + " collection_status=?,object_count=?,started_at=COALESCE(started_at,clock_timestamp()),finished_at=clock_timestamp(),detection_stage_status=?,validation_stage_status=?,validation_required=?,validation_reason_code=?"
                                + " WHERE run_id=?",
                            collection,
                            fetched ? 1 : 0,
                            fetched ? "SUCCEEDED" : "SKIPPED",
                            validation,
                            "SUCCEEDED".equals(validation),
                            result.reasonCode(),
                            job.runId());
                })) throw new SecretJobFailure(SecretJobFailureCode.LEASE_EXPIRED, true);
    }
}
