package com.logssey.iacworker;

import java.time.OffsetDateTime;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class IacJobExecutionService {

    private final IacJobRepository repository;
    private final IacJobProperties properties;
    private final TransactionTemplate transaction;

    public IacJobExecutionService(IacJobRepository repository, IacJobProperties properties,
                                  PlatformTransactionManager transactionManager) {
        this.repository = repository;
        this.properties = properties;
        this.transaction = new TransactionTemplate(transactionManager);
    }

    public Optional<ClaimedIacJob> claimNextJob(IacJobKind kind) {
        Objects.requireNonNull(kind, "kind");
        return Objects.requireNonNull(transaction.execute(status -> {
            OffsetDateTime now = repository.databaseNow();
            var available = repository.lockAvailable(now, 1, kind);
            if (available.isEmpty()) {
                return Optional.<ClaimedIacJob>empty();
            }
            // A new token on every attempt fences a worker that wakes up after its lease expires.
            return Optional.of(repository.claim(available.getFirst(), now.plus(properties.leaseDuration()),
                    UUID.randomUUID().toString()));
        }));
    }

    public int recoverExpiredJobs() {
        return Objects.requireNonNull(transaction.execute(status -> {
            OffsetDateTime now = repository.databaseNow();
            var expired = repository.lockExpired(now, properties.batchSize());
            for (var row : expired) {
                transitionFailure(row, now, IacJobFailureCode.LEASE_EXPIRED.name(), true);
            }
            return expired.size();
        }));
    }

    public boolean renewLease(long jobId, String leaseToken) {
        return Objects.requireNonNull(transaction.execute(status ->
                repository.renew(jobId, leaseToken, properties.leaseDuration())));
    }

    /**
     * Execute only short database writes here; never call Neo4j, AWS or GitHub inside this lock.
     * Processors write their results through this fence so a worker that lost its lease writes nothing.
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

    public boolean complete(long jobId, String leaseToken) {
        return Objects.requireNonNull(transaction.execute(status -> {
            var row = repository.lockJob(jobId);
            OffsetDateTime now = repository.databaseNow();
            if (row.isEmpty() || !row.get().isLiveLease(leaseToken, now)) {
                return false;
            }
            repository.finish(row.get(), now);
            return true;
        }));
    }

    public boolean fail(long jobId, String leaseToken, IacJobFailureCode code, boolean retryable) {
        Objects.requireNonNull(code, "code");
        return Objects.requireNonNull(transaction.execute(status -> {
            var row = repository.lockJob(jobId);
            OffsetDateTime now = repository.databaseNow();
            if (row.isEmpty() || !row.get().isLiveLease(leaseToken, now)) {
                return false;
            }
            transitionFailure(row.get(), now, code.name(), retryable);
            return true;
        }));
    }

    public int deleteExpiredPlans() {
        return Objects.requireNonNull(transaction.execute(status ->
                repository.deleteExpiredPlans(repository.databaseNow())));
    }

    private void transitionFailure(IacJobRepository.JobRow row, OffsetDateTime now, String code, boolean retryable) {
        if (retryable && row.attemptNo() < row.maxAttempts()) {
            repository.retry(row, now.plus(properties.retryDelay(row.attemptNo())), code);
        } else {
            repository.failPermanently(row, now, code);
        }
    }
}
