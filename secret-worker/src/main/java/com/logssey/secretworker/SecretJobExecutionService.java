package com.logssey.secretworker;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Service
public class SecretJobExecutionService {

    private final SecretJobRepository repository;
    private final SecretJobProperties properties;
    private final TransactionTemplate transaction;

    public SecretJobExecutionService(SecretJobRepository repository, SecretJobProperties properties,
                                     PlatformTransactionManager transactionManager) {
        this.repository = repository;
        this.properties = properties;
        this.transaction = new TransactionTemplate(transactionManager);
    }

    public com.logssey.secret.run.progress.core.ScanExecutionObserver observer(ClaimedSecretJob job, Long scopeId) {
        return repository.observer(job, scopeId);
    }

    public Optional<ClaimedSecretJob> claimNextJob() {
        return claimNextJob(null);
    }

    public Optional<ClaimedSecretJob> claimNextJob(String provider) {
        return Objects.requireNonNull(transaction.execute(status -> {
            OffsetDateTime now = repository.databaseNow();
            var available = repository.lockAvailable(now, 1, provider);
            if (available.isEmpty() || !repository.connectionAvailableForClaim(available.getFirst().jobId())) {
                return Optional.<ClaimedSecretJob>empty();
            }
                            // A new token on every attempt fences a worker that wakes up after its
                            // lease expires.
            return Optional.of(repository.claim(available.getFirst(), now, now.plus(properties.leaseDuration()),
                    UUID.randomUUID().toString()));
        }));
    }

    public int recoverExpiredJobs() {
        return Objects.requireNonNull(transaction.execute(status -> {
            OffsetDateTime now = repository.databaseNow();
            var expired = repository.lockExpired(now, properties.batchSize());
            for (var row : expired) {
                transitionFailure(row, now, "LEASE_EXPIRED", true);
            }
            return expired.size();
        }));
    }

    public boolean renewLease(long jobId, String leaseToken) {
        return Objects.requireNonNull(transaction.execute(status -> {
                            // The database checks the live lease and computes the new deadline
                            // atomically.
            return repository.renew(jobId, leaseToken, properties.leaseDuration());
        }));
    }

    /**
     * Execute only short database persistence work here; never perform network calls inside this
     * lock. This is the write fence that future collectors must use for run/scope/result updates.
     */
    public boolean persistIfLeased(long jobId, String leaseToken, Runnable databaseWrites) {
        Objects.requireNonNull(databaseWrites, "databaseWrites");
        return Objects.requireNonNull(transaction.execute(status -> {
            var row = repository.lockJob(jobId);
            if (row.isEmpty() || !row.get().isLiveLease(leaseToken, repository.databaseNow())) {
                return false;
            }
            databaseWrites.run();
            return true;
        }));
    }

    /** Records stage facts only after the scope callback, fenced by the same live lease. */
    public boolean recordScopeEvidence(long jobId, String token, long runScopeId, boolean validationFailed) {
        return persistIfLeased(jobId, token, () -> repository.recordScopeEvidence(runScopeId, validationFailed));
    }

    /** Succeeds only after all stages and snapshotted scopes have terminal results. */
    public boolean complete(long jobId, String leaseToken) {
        return Objects.requireNonNull(transaction.execute(status -> {
            var row = repository.lockJob(jobId);
            if (row.isEmpty()) {
                return false;
            }
            OffsetDateTime now = repository.databaseNow();
            if (!row.get().isLiveLease(leaseToken, now)) {
                return false;
            }
            var run = repository.runState(row.get().runId());
                            if (repository.isCredentialValidation(jobId)) {
                                if (!java.util.Set.of("SUCCEEDED", "PARTIAL", "SKIPPED", "FAILED")
                                        .contains(run.validation())) return false;
                                repository.startResult(row.get());
                                repository.finishValidation(
                                        row.get(),
                                        now,
                                        "PARTIAL".equals(run.validation())
                                                ? "PARTIAL"
                                                : "SKIPPED".equals(run.validation())
                                                        ? "SKIPPED"
                                                        : "SUCCEEDED");
                                return true;
                            }
            var scopes = repository.scopeState(row.get().runId());
            if (!canComplete(run, scopes)) {
                return false;
            }
            boolean partial = "PARTIAL".equals(run.collection()) || "PARTIAL".equals(run.detection())
                    || "PARTIAL".equals(run.validation()) || scopes.incomplete() > 0;
            repository.startResult(row.get());
            repository.finish(row.get(), now, partial ? "PARTIAL" : "SUCCEEDED");
            return true;
        }));
    }

    public boolean fail(long jobId, String leaseToken, SecretJobFailureCode code, boolean retryable) {
        Objects.requireNonNull(code, "code");
        return Objects.requireNonNull(transaction.execute(status -> {
            var row = repository.lockJob(jobId);
            if (row.isEmpty()) {
                return false;
            }
            OffsetDateTime now = repository.databaseNow();
            if (!row.get().isLiveLease(leaseToken, now)) {
                return false;
            }
            transitionFailure(row.get(), now, code.name(), retryable);
            return true;
        }));
    }

    private void transitionFailure(SecretJobRepository.JobRow row, OffsetDateTime now,
                                   String code, boolean retryable) {
        if (retryable && row.attemptNo() < row.maxAttempts()) {
            if (!repository.retry(row, now, now.plus(properties.retryDelay(row.attemptNo())), code))
                repository.failPermanently(row, now, SecretJobFailureCode.VALIDATION_DEADLINE_EXCEEDED.name());
        } else {
            repository.failPermanently(row, now, code);
        }
    }

    private boolean canComplete(SecretJobRepository.RunState run, SecretJobRepository.ScopeState scopes) {
        if (!"RUNNING".equals(run.result()) || scopes.total() == 0 || scopes.terminal() != scopes.total()
                || scopes.usable() == 0 || scopes.uncompleted() > 0) {
            return false;
        }
        if (!("SUCCEEDED".equals(run.collection()) || "PARTIAL".equals(run.collection()))
                || !("SUCCEEDED".equals(run.detection()) || "PARTIAL".equals(run.detection())
                     || "SKIPPED".equals(run.detection()))
                || !("SUCCEEDED".equals(run.validation()) || "PARTIAL".equals(run.validation())
                     || "SKIPPED".equals(run.validation()))) {
            return false;
        }
        return (!"SUCCEEDED".equals(run.collection()) || scopes.incomplete() == 0)
                && (!"SKIPPED".equals(run.detection()) || scopes.objectTotal() == 0);
    }
}
