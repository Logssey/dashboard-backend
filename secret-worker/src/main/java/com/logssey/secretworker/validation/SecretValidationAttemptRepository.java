package com.logssey.secretworker.validation;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Objects;

import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import com.logssey.secretworker.SecretJobExecutionService;
import com.logssey.secretworker.detection.SecretFindingNormalizer;

/**
 * Stores a safe result only after the worker has validated outside a database transaction.
 * The write itself is fenced by the live job lease and bound to a discovered credential.
 */
@Repository
public class SecretValidationAttemptRepository {
    private static final String ENDPOINT_CLASS = "AWS_STS";

    private final JdbcTemplate jdbc;
    private final SecretJobExecutionService jobs;

    public SecretValidationAttemptRepository(JdbcTemplate jdbc, SecretJobExecutionService jobs) {
        this.jdbc = Objects.requireNonNull(jdbc);
        this.jobs = Objects.requireNonNull(jobs);
    }

    /** Returns false when the lease is lost; no validation row is written in that case. */
    public boolean recordIfLeased(long jobId, String leaseToken, long runId,
                                  SecretFindingNormalizer.Credential credential, AwsValidationResult result) {
        validateInput(jobId, leaseToken, runId, credential, result);
        try {
            return jobs.persistIfLeased(jobId, leaseToken,
                    () -> insertVerifiedAttempt(jobId, runId, credential, result));
        } catch (DataAccessException error) {
            // Database errors may include SQL parameters, so never propagate the original exception.
            throw new IllegalStateException("VALIDATION_PERSISTENCE_FAILED");
        }
    }

    private void insertVerifiedAttempt(long jobId, long runId,
                                       SecretFindingNormalizer.Credential credential, AwsValidationResult result) {
        boolean confirmed = credential.componentState().equals("CONFIRMED");
        String identityColumn = confirmed ? "c.fingerprint" : "c.candidate_locator";
        byte[] identity = confirmed ? credential.fingerprint() : credential.candidateLocator();
        List<Long> ids = jdbc.query("""
                SELECT c.credential_set_id
                FROM secret_credential_sets c
                JOIN secret_occurrences o ON o.credential_set_id = c.credential_set_id
                JOIN secret_scan_runs r ON r.run_id = o.last_seen_run_id
                WHERE r.run_id = ? AND r.job_id = ? AND o.presence_status = 'PRESENT'
                  AND c.issuer = 'AWS' AND c.credential_type = ?
                  AND c.component_state = ? AND c.fingerprint_key_version = ?
                  AND """ + " " + identityColumn + " = ? LIMIT 1",
                (rs, row) -> rs.getLong("credential_set_id"), runId, jobId,
                credential.credentialType(), credential.componentState(),
                credential.fingerprintKeyVersion(), identity);
        if (ids.isEmpty()) throw new IllegalArgumentException("VALIDATION_IDENTITY_NOT_FOUND");
        Instant completed = result.checkedAt() == null ? result.evaluatedAt() : result.checkedAt();
        jdbc.update("""
                INSERT INTO secret_validation_attempts
                    (credential_set_id, run_id, job_id, validator_id, validator_version,
                     endpoint_class, requested_at, completed_at, provider_checked_at, result, reason_code)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, ids.getFirst(), runId, jobId, result.method(), result.version(), ENDPOINT_CLASS,
                utc(result.evaluatedAt()), utc(completed),
                result.checkedAt() == null ? null : utc(result.checkedAt()),
                result.status().name(), result.reason().name());
    }

    private static void validateInput(long jobId, String leaseToken, long runId,
                                      SecretFindingNormalizer.Credential credential, AwsValidationResult result) {
        if (jobId <= 0 || runId <= 0 || leaseToken == null || leaseToken.isBlank()
                || credential == null || result == null || result.status() == null || result.reason() == null
                || result.evaluatedAt() == null || !AwsValidationResult.METHOD.equals(result.method())
                || !AwsValidationResult.VERSION.equals(result.version())
                || !"AWS".equals(credential.issuer())
                || !List.of("AWS_ACCESS_KEY_PAIR", "AWS_TEMPORARY_CREDENTIALS")
                        .contains(credential.credentialType())
                || !List.of("CONFIRMED", "CANDIDATE").contains(credential.componentState())
                || credential.fingerprintKeyVersion() == null
                || (credential.componentState().equals("CONFIRMED") && credential.fingerprint() == null)
                || (credential.componentState().equals("CANDIDATE") && credential.candidateLocator() == null)
                || (credential.componentState().equals("CANDIDATE")
                    && result.status() != AwsValidationResult.Status.UNCHECKED)
                || (result.status() != AwsValidationResult.Status.UNCHECKED && result.checkedAt() == null)
                || (result.status() == AwsValidationResult.Status.UNCHECKED && result.checkedAt() != null)
                || !consistentReason(result.status(), result.reason())
                || (result.checkedAt() != null && result.checkedAt().isBefore(result.evaluatedAt()))) {
            throw new IllegalArgumentException("INVALID_VALIDATION_RESULT");
        }
    }

    private static boolean consistentReason(AwsValidationResult.Status status, AwsValidationResult.Reason reason) {
        return switch (status) {
            case VALID -> reason == AwsValidationResult.Reason.AUTHENTICATED;
            case INVALID -> reason == AwsValidationResult.Reason.INVALID_ACCESS_KEY
                    || reason == AwsValidationResult.Reason.EXPIRED_SESSION;
            case UNKNOWN -> List.of(AwsValidationResult.Reason.SIGNATURE_AMBIGUOUS,
                    AwsValidationResult.Reason.ACCESS_AMBIGUOUS, AwsValidationResult.Reason.RATE_LIMITED,
                    AwsValidationResult.Reason.PROVIDER_UNAVAILABLE,
                    AwsValidationResult.Reason.CLIENT_FAILURE).contains(reason);
            case UNCHECKED -> List.of(AwsValidationResult.Reason.DISABLED,
                    AwsValidationResult.Reason.SYNTHETIC_FIXTURE,
                    AwsValidationResult.Reason.INCOMPLETE_PAIR,
                    AwsValidationResult.Reason.MISSING_SESSION_TOKEN).contains(reason);
        };
    }

    private static OffsetDateTime utc(Instant instant) {
        return instant.atOffset(ZoneOffset.UTC);
    }
}
