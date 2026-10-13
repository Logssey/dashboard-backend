package com.logssey.secret.run;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Set;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class SecretRunService {

    private static final Set<String> PUBLIC_FAILURE_CODES = Set.of(
            "LEASE_EXPIRED", "PROCESSOR_FAILURE", "INCOMPLETE_RUN", "SOURCE_UNAVAILABLE",
            "SOURCE_ACCESS_DENIED", "SOURCE_RATE_LIMITED", "DETECTOR_TEMPORARY",
            "VALIDATOR_TEMPORARY");

    private final SecretRunRepository repository;
    private final TransactionTemplate transaction;

    public SecretRunService(SecretRunRepository repository, PlatformTransactionManager transactionManager) {
        this.repository = repository;
        this.transaction = new TransactionTemplate(transactionManager);
    }

    public SecretRunAcceptedResponse register(SecretRunRequest request, String loginId) {
        if (request == null || request.connectionId() == null || request.connectionId() <= 0
                || request.idempotencyKey() != null
                && !request.idempotencyKey().matches("[A-Za-z0-9._:-]{1,120}")) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        try {
            return Objects.requireNonNull(transaction.execute(ignored -> {
                var actor = requireAdmin(loginId);
                String key = request.idempotencyKey() == null
                        ? null : hashIdempotencyKey(actor.id(), request.idempotencyKey());
                if (key != null) {
                    repository.lockIdempotencyKey(advisoryLockKey(key));
                    var prior = repository.byIdempotencyKey(key);
                    if (prior.isPresent()) {
                        var run = prior.orElseThrow();
                        if (run.connectionId() != request.connectionId()
                                || !Objects.equals(run.requestedBy(), actor.id())) {
                            throw new ApiException(ErrorCode.CONFLICT);
                        }
                        var replayConnection = repository.lockConnection(run.connectionId())
                                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
                        if (!"GITHUB".equals(replayConnection.provider())) {
                            throw new ApiException(ErrorCode.CONFLICT);
                        }
                        return accepted(run);
                    }
                }

                var connection = repository.lockConnection(request.connectionId())
                        .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
                if (!"ACTIVE".equals(connection.status()) || !"GITHUB".equals(connection.provider())) {
                    throw new ApiException(ErrorCode.CONFLICT);
                }
                var active = repository.activeRun(connection.id());
                if (active.isPresent()) {
                    if (key != null) {
                        // A different key cannot be attached to an already reserved job.
                        throw new ApiException(ErrorCode.CONFLICT);
                    }
                    return accepted(active.orElseThrow());
                }
                return accepted(repository.reserve(connection, actor.id(), key, repository.databaseNow()));
            }));
        } catch (SecretRunRepository.NoApprovedScopeException e) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
    }

    public SecretRunStatusResponse status(long runId, String loginId) {
        requireAdmin(loginId);
        if (runId <= 0) {
            throw new ApiException(ErrorCode.NOT_FOUND);
        }
        var run = repository.runStatus(runId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        return new SecretRunStatusResponse(run.runId(), run.connectionId(), run.triggerType(),
                displayStatus(run.jobStatus(), run.resultStatus()), run.collectionStatus(),
                run.detectionStatus(), run.validationStatus(), run.scopeCount(),
                run.completedScopeCount(), run.incompleteScopeCount(), run.objectCount(),
                run.attemptNo(), run.maxAttempts(), run.requestedAt(), run.startedAt(),
                run.finishedAt(), run.availableAt(), safeFailureCode(
                        run.runFailureCode() == null ? run.jobFailureCode() : run.runFailureCode()));
    }

    private SecretRunRepository.Actor requireAdmin(String loginId) {
        if (loginId == null || loginId.isBlank()) {
            throw new ApiException(ErrorCode.UNAUTHENTICATED);
        }
        var actor = repository.actor(loginId)
                .orElseThrow(() -> new ApiException(ErrorCode.UNAUTHENTICATED));
        if (!"ADMIN".equals(actor.role())) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
        return actor;
    }

    private static SecretRunAcceptedResponse accepted(SecretRunRepository.JobRun run) {
        return new SecretRunAcceptedResponse(run.runId(), displayStatus(run.jobStatus(), run.resultStatus()));
    }

    private static String displayStatus(String jobStatus, String resultStatus) {
        return switch (jobStatus) {
            case "PENDING" -> "PENDING";
            case "LEASED" -> "RUNNING";
            case "SUCCEEDED" -> resultStatus;
            case "FAILED" -> "FAILED";
            case "CANCELLED" -> "CANCELLED";
            default -> "UNKNOWN";
        };
    }

    private static String safeFailureCode(String code) {
        if (code == null) {
            return null;
        }
        return PUBLIC_FAILURE_CODES.contains(code) ? code : "UNSPECIFIED_FAILURE";
    }

    private static String hashIdempotencyKey(long actorId, String key) {
        try {
            var digest = MessageDigest.getInstance("SHA-256");
            digest.update(ByteBuffer.allocate(Long.BYTES).putLong(actorId).array());
            digest.update((byte) 0);
            digest.update(key.getBytes(StandardCharsets.US_ASCII));
            return "manual:" + HexFormat.of().formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private static long advisoryLockKey(String hashedKey) {
        return Long.parseUnsignedLong(hashedKey.substring("manual:".length(), "manual:".length() + 16), 16);
    }
}
