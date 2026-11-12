package com.logssey.secret.run;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Set;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.access.SecretAccessService;
import com.logssey.secret.access.SecretRole;
import com.logssey.secret.command.SecretCommandExecutor;
import com.logssey.secret.command.SecretCommandResult;

import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class SecretRunService {

    private static final Set<String> PUBLIC_FAILURE_CODES = Set.of(
            "LEASE_EXPIRED", "PROCESSOR_FAILURE", "INCOMPLETE_RUN", "SOURCE_UNAVAILABLE",
            "SOURCE_ACCESS_DENIED", "SOURCE_RATE_LIMITED", "DETECTOR_TEMPORARY",
            "VALIDATOR_TEMPORARY", "VALIDATION_ATTEMPT_FAILED", "VALIDATION_INCONCLUSIVE",
            "AWS_ROOT_ACCESS_KEYS_PRESENT", "AWS_ROOT_KEY_COVERAGE_UNKNOWN");
    private static final Set<String> PUBLIC_SCOPE_TYPES = Set.of(
            "GITHUB_REPOSITORY_FILES", "IAM_ACCESS_KEY_METADATA",
            "AWS_SECRETS_MANAGER_METADATA", "AWS_SSM_PARAMETER_METADATA",
            "AWS_S3_BUCKET_METADATA", "AWS_SECRETS_MANAGER_VALUE",
            "AWS_SSM_PARAMETER_VALUE", "AWS_S3_OBJECT_CONTENT", "NOTION_PAGE_CONTENT");
    private static final Set<String> PUBLIC_SCOPE_GAPS = Set.of(
            "NOTION_ACCESS_DENIED", "NOTION_NOT_FOUND", "NOTION_RATE_LIMITED", "NOTION_UNAVAILABLE",
            "NOTION_RESPONSE_TOO_LARGE", "NOTION_MALFORMED_RESPONSE", "NOTION_TOKEN_UNAVAILABLE",
            "NOTION_PAGE_TRASHED", "NOTION_CONTENT_TRUNCATED", "NOTION_UNATTRIBUTED_FINDINGS",
            "INVALID_APPROVED_SCOPE", "AWS_INVALID_APPROVED_SCOPE", "AWS_SERVICE_UNSUPPORTED",
            "AWS_ACCOUNT_MISMATCH", "AWS_ACCESS_DENIED", "AWS_RATE_LIMITED",
            "AWS_UNAVAILABLE", "AWS_SOURCE_UNAVAILABLE", "AWS_API_ERROR",
            "AWS_INVALID_RESPONSE", "AWS_MALFORMED_RESPONSE", "AWS_PAGE_LIMIT",
            "AWS_OBJECT_LIMIT", "AWS_PAGINATION_LOOP", "AWS_USER_LIMIT", "AWS_KEY_LIMIT",
            "AWS_LAST_USED_UNAVAILABLE", "AWS_ROOT_ACCESS_KEYS_PRESENT",
            "AWS_ROOT_KEY_COVERAGE_UNKNOWN", "AWS_CONTENT_READ_DISABLED",
            "AWS_CONTENT_ACCESS_DENIED", "AWS_CONTENT_NOT_FOUND",
            "AWS_CONTENT_RATE_LIMITED", "AWS_CONTENT_SOURCE_UNAVAILABLE",
            "AWS_CONTENT_OBJECT_TOO_LARGE", "AWS_CONTENT_NON_TEXT",
            "AWS_CONTENT_CONSUMER_FAILED", "AWS_CONTENT_PROCESSING_FAILED",
            "DETECTOR_INPUT_TOO_LARGE", "DETECTOR_OUTPUT_TOO_LARGE",
            "DETECTOR_TOOL_UNAVAILABLE", "DETECTOR_UNSUPPORTED_VERSION",
            "DETECTOR_TOOL_TIMEOUT", "DETECTOR_TOOL_EXIT", "DETECTOR_INVALID_REPORT",
            "DETECTOR_NORMALIZATION_INCOMPLETE",
            "DETECTOR_TOOL_IO_ERROR", "DETECTOR_INTERRUPTED", "RESULT_PERSISTENCE_FAILED",
            "GITHUB_PATH_NOT_FOUND",
            "GITHUB_ACCESS_DENIED", "GITHUB_RATE_LIMITED", "GITHUB_SOURCE_UNAVAILABLE",
            "GITHUB_API_ERROR", "GITHUB_MALFORMED_RESPONSE",
            "GITHUB_TREE_TRUNCATED", "GITHUB_TREE_LIMIT", "GITHUB_FILE_LIMIT",
            "GITHUB_FILE_TOO_LARGE", "GITHUB_TOTAL_BYTES_LIMIT",
            "GITHUB_BINARY_FILE", "GITHUB_GIT_LFS_POINTER",
            "GITHUB_UNSUPPORTED_OBJECT", "GITHUB_DEPTH_LIMIT", "GITHUB_CONSUMER_FAILED");
    private static final String REGION = "[a-z]{2}(?:-[a-z0-9]+){1,3}-[0-9]+";
    private static final Pattern SECRETS_REF = Pattern.compile(
            "^aws://[0-9]{12}/(" + REGION + ")/secrets-manager/all$");
    private static final Pattern PARAMETERS_REF = Pattern.compile(
            "^aws://[0-9]{12}/(" + REGION + ")/ssm/parameters$");
    private static final Pattern BUCKETS_REF = Pattern.compile(
            "^aws://[0-9]{12}/global/s3/buckets$");
    private static final Pattern IAM_REF = Pattern.compile(
            "^aws://[0-9]{12}/global/iam/access-keys$");
    private static final String EXACT_SEGMENT = "([^/?#%*]|%[0-9A-Fa-f]{2})+";
    private static final Pattern SECRET_VALUE_REF = Pattern.compile(
            "^aws://[0-9]{12}/(" + REGION + ")/secrets-manager/secret/" + EXACT_SEGMENT + "$");
    private static final Pattern PARAMETER_VALUE_REF = Pattern.compile(
            "^aws://[0-9]{12}/(" + REGION + ")/ssm/parameter/" + EXACT_SEGMENT + "$");
    private static final Pattern OBJECT_CONTENT_REF = Pattern.compile(
            "^aws://[0-9]{12}/(" + REGION + ")/s3/object/"
                    + "[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/" + EXACT_SEGMENT + "$");

    private final SecretRunRepository repository;
    private final TransactionTemplate transaction;
    private final SecretAccessService access;
    private final SecretCommandExecutor commands;

    public SecretRunService(SecretRunRepository repository, PlatformTransactionManager transactionManager,
                            SecretAccessService access, SecretCommandExecutor commands) {
        this.repository = repository;
        this.transaction = new TransactionTemplate(transactionManager);
        this.access = access;
        this.commands = commands;
    }

    public SecretRunAcceptedResponse register(SecretRunRequest request, String loginId) {
        if (request == null || request.connectionId() == null || request.connectionId() <= 0
                || request.idempotencyKey() != null
                && !request.idempotencyKey().matches("[A-Za-z0-9._:-]{1,120}")) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        var principal = access.requirePrincipal(loginId);
        String commandKey = request.idempotencyKey() == null
                ? java.util.UUID.randomUUID().toString() : request.idempotencyKey();
        var result = commands.execute(principal, SecretCommandExecutor.Kind.MANUAL_SCAN,
                commandKey, SecretCommandExecutor.digestSafeIds(request.connectionId()),
                () -> {
                    access.requireConnectionRole(principal, request.connectionId(), SecretRole.OPERATIONS);
                    var connection = repository.lockConnection(request.connectionId())
                            .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
                    if (!supportedProvider(connection.provider()) || !repository.hasSupportedScope(connection))
                        throw new ApiException(ErrorCode.CONFLICT);
                },
                () -> {
                    var accepted = registerWithinTransaction(request, loginId);
                    return new SecretCommandResult(accepted.runId(), 0,
                            SecretCommandResult.Status.valueOf(accepted.status()));
                });
        return new SecretRunAcceptedResponse(result.targetId(), result.status().name());
    }

    private SecretRunAcceptedResponse registerWithinTransaction(SecretRunRequest request, String loginId) {
        try {
            return Objects.requireNonNull(transaction.execute(ignored -> {
                var principal = access.requirePrincipal(loginId);
                access.requireConnectionRole(principal, request.connectionId(), SecretRole.OPERATIONS);
                var actor = new SecretRunRepository.Actor(principal.userId(), null);
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
                        if (!supportedProvider(replayConnection.provider())
                                || !repository.hasSupportedScope(replayConnection)) {
                            throw new ApiException(ErrorCode.CONFLICT);
                        }
                        return accepted(run);
                    }
                }

                var connection = repository.lockConnection(request.connectionId())
                        .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
                if (!"ACTIVE".equals(connection.status()) || !supportedProvider(connection.provider())) {
                    throw new ApiException(ErrorCode.CONFLICT);
                }
                if (!repository.hasSupportedScope(connection)) {
                    throw new ApiException(ErrorCode.CONFLICT);
                }
                if (repository.hasActiveRevalidation(connection.id())) {
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
        var principal = access.requirePrincipal(loginId);
        access.requireAnyRole(principal);
        if (runId <= 0) {
            throw new ApiException(ErrorCode.NOT_FOUND);
        }
        var run = repository.runStatus(runId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        access.requireConnectionFactsRead(principal, run.connectionId());
        List<SecretRunScopeResultResponse> scopeResults = repository.safeScopes(runId);
        return new SecretRunStatusResponse(run.runId(), run.connectionId(), run.triggerType(),
                displayStatus(run.jobStatus(), run.resultStatus()), run.collectionStatus(),
                run.detectionStatus(), run.validationStatus(), run.scopeCount(),
                run.completedScopeCount(), run.incompleteScopeCount(), run.objectCount(),
                run.attemptNo(), run.maxAttempts(), run.requestedAt(), run.startedAt(),
                run.finishedAt(), run.availableAt(), safeFailureCode(
                        run.runFailureCode() == null ? run.jobFailureCode() : run.runFailureCode()),
                scopeResults, repository.coverage(runId,loginId));
    }

    @Transactional(readOnly = true)
    public SecretRunListResponse list(int page, int size, String loginId) {
        var principal = access.requirePrincipal(loginId);
        access.requireAnyRole(principal);
        if (page < 0 || page > 1_000_000 || size < 1 || size > 100) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        long total = repository.countRuns(principal.userId());
        var items = repository.listRuns(principal.userId(), size, (long) page * size).stream().map(entry -> {
            var run = entry.status();
            return new SecretRunListItemResponse(run.runId(), run.connectionId(),
                    entry.provider(), "연결 #"+run.connectionId(), run.triggerType(),
                    displayStatus(run.jobStatus(), run.resultStatus()), run.collectionStatus(),
                    run.detectionStatus(), run.validationStatus(), run.scopeCount(),
                    run.completedScopeCount(), run.incompleteScopeCount(), run.objectCount(),
                    run.requestedAt(), run.startedAt(), run.finishedAt(),
                    safeFailureCode(run.runFailureCode() == null
                            ? run.jobFailureCode() : run.runFailureCode()), repository.coverage(run.runId(),loginId));
        }).toList();
        return new SecretRunListResponse(items, total, page, size);
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

    static String safeFailureCode(String code) {
        if (code == null) {
            return null;
        }
        return PUBLIC_FAILURE_CODES.contains(code) || PUBLIC_SCOPE_GAPS.contains(code)
                ? code : "UNSPECIFIED_FAILURE";
    }

    private static SecretRunScopeResultResponse scopeResult(SecretRunRepository.RunScope scope) {
        String type = PUBLIC_SCOPE_TYPES.contains(scope.contentType())
                ? scope.contentType() : "UNSUPPORTED";
        String region = region(type, scope.approvedRef());
        String gap = scope.failureCode() == null ? scope.unsupportedReason() : scope.failureCode();
        return new SecretRunScopeResultResponse(scope.runScopeId(), type, region,
                scope.collectionStatus(), scope.objectCount(), safeFailureCode(gap));
    }

    static String region(String type, String approvedRef) {
        if (approvedRef == null) return null;
        if ("IAM_ACCESS_KEY_METADATA".equals(type)) {
            return IAM_REF.matcher(approvedRef).matches() ? "global" : null;
        }
        if ("AWS_S3_BUCKET_METADATA".equals(type)) {
            return BUCKETS_REF.matcher(approvedRef).matches() ? "global" : null;
        }
        Pattern pattern = switch (type) {
            case "AWS_SECRETS_MANAGER_METADATA" -> SECRETS_REF;
            case "AWS_SSM_PARAMETER_METADATA" -> PARAMETERS_REF;
            case "AWS_SECRETS_MANAGER_VALUE" -> SECRET_VALUE_REF;
            case "AWS_SSM_PARAMETER_VALUE" -> PARAMETER_VALUE_REF;
            case "AWS_S3_OBJECT_CONTENT" -> OBJECT_CONTENT_REF;
            default -> null;
        };
        if (pattern == null) return null;
        Matcher match = pattern.matcher(approvedRef);
        return match.matches() ? match.group(1) : null;
    }

    private static boolean supportedProvider(String provider) {
        return "GITHUB".equals(provider) || "AWS".equals(provider) || "NOTION".equals(provider);
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
