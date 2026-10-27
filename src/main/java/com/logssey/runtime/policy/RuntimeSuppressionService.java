package com.logssey.runtime.policy;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.runtime.ingest.RuntimeHashing;
import com.logssey.runtime.policy.RuntimeSuppressionRepository.CurrentSuppression;
import com.logssey.runtime.policy.RuntimeSuppressionRepository.IdempotentSuppression;
import com.logssey.runtime.policy.RuntimeSuppressionRepository.ValidatedSuppression;
import com.logssey.runtime.policy.dto.RuntimeSuppressionCreateRequest;
import com.logssey.runtime.policy.dto.RuntimeSuppressionResponse;
import com.logssey.runtime.policy.dto.RuntimeSuppressionRevokeRequest;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class RuntimeSuppressionService {

    private static final Duration MAX_DURATION = Duration.ofDays(30);
    private static final Set<String> REASONS = Set.of(
            "APPROVED_OPERATION", "PLATFORM_COMPONENT", "TEMPORARY_MAINTENANCE");
    private static final Set<String> OPERATIONS = Set.of("EXEC", "OPEN", "WRITE");
    private static final Pattern EVIDENCE = Pattern.compile(
            "^(TICKET|CHANGE):[A-Z][A-Z0-9]{1,15}-[1-9][0-9]{0,12}$");

    private final RuntimeSuppressionRepository repository;

    public RuntimeSuppressionService(RuntimeSuppressionRepository repository) {
        this.repository = repository;
    }

    public List<RuntimeSuppressionResponse> findAll(String loginId, boolean activeOnly) {
        requireAdmin(loginId);
        return repository.findAll(activeOnly);
    }

    @Transactional
    public RuntimeSuppressionResponse create(String loginId, RuntimeSuppressionCreateRequest request) {
        long actorId = requireAdmin(loginId);
        ValidatedSuppression validated = validate(request, Instant.now());
        if (!repository.ruleExists(validated.ruleKey())) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "등록되지 않은 런타임 규칙입니다.");
        }
        String digest = digest(validated);
        OptionalResult existing = idempotent(actorId, validated.idempotencyKey(), digest);
        if (existing.response() != null) {
            return existing.response();
        }

        Long insertedId = repository.insert(actorId, validated, digest).orElse(null);
        if (insertedId == null) {
            return idempotent(actorId, validated.idempotencyKey(), digest).required();
        }
        return repository.find(insertedId).orElseThrow(() -> new ApiException(ErrorCode.INTERNAL_ERROR));
    }

    @Transactional
    public RuntimeSuppressionResponse revoke(String loginId, long suppressionId,
                                             RuntimeSuppressionRevokeRequest request) {
        long actorId = requireAdmin(loginId);
        if (request == null || request.version() < 1) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        String reason = required(request.reason(), 10, 500, "취소 사유");
        CurrentSuppression current = repository.findCurrentForUpdate(suppressionId)
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        if (current.revoked() || current.version() != request.version()) {
            throw new ApiException(ErrorCode.CONFLICT, "예외 정책이 이미 변경되었습니다.");
        }
        if (repository.revoke(suppressionId, actorId, request.version(), reason) != 1) {
            throw new ApiException(ErrorCode.CONFLICT, "예외 정책이 이미 변경되었습니다.");
        }
        return repository.find(suppressionId).orElseThrow(() -> new ApiException(ErrorCode.INTERNAL_ERROR));
    }

    private long requireAdmin(String loginId) {
        if (loginId == null || loginId.isBlank()) {
            throw new ApiException(ErrorCode.UNAUTHENTICATED);
        }
        return repository.adminUserId(loginId)
                .orElseThrow(() -> new ApiException(ErrorCode.FORBIDDEN));
    }

    private OptionalResult idempotent(long actorId, String idempotencyKey, String digest) {
        IdempotentSuppression existing = repository.findByIdempotency(actorId, idempotencyKey).orElse(null);
        if (existing == null) {
            return new OptionalResult(null);
        }
        if (!existing.requestDigest().equals(digest)) {
            throw new ApiException(ErrorCode.CONFLICT, "같은 멱등키가 다른 요청에 사용되었습니다.");
        }
        return new OptionalResult(repository.find(existing.suppressionId())
                .orElseThrow(() -> new ApiException(ErrorCode.INTERNAL_ERROR)));
    }

    static ValidatedSuppression validate(RuntimeSuppressionCreateRequest request, Instant now) {
        if (request == null) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        String ruleKey = required(request.ruleKey(), 1, 40, "규칙 키");
        String clusterId = required(request.clusterId(), 1, 80, "클러스터");
        String namespace = optional(request.namespace(), 120, "네임스페이스");
        String workload = optional(request.workloadName(), 200, "워크로드");
        String executable = optional(request.processExecutable(), 500, "실행 파일");
        String targetPrefix = optional(request.targetNamePrefix(), 1000, "대상 경로");
        String operation = optional(request.operation(), 40, "동작");
        if (namespace == null && workload == null && executable == null && targetPrefix == null) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "예외에는 하나 이상의 구체적인 범위가 필요합니다.");
        }
        if (operation != null && !OPERATIONS.contains(operation)) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "operation은 EXEC, OPEN, WRITE 중 하나여야 합니다.");
        }
        if (targetPrefix != null && !targetPrefix.startsWith("/")) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "대상 경로는 절대 경로여야 합니다.");
        }
        if (executable != null && !executable.startsWith("/")) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "실행 파일은 절대 경로여야 합니다.");
        }
        String reason = required(request.reasonCode(), 1, 40, "사유 코드");
        if (!REASONS.contains(reason)) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "지원하지 않는 예외 사유입니다.");
        }
        String evidenceRef = required(request.evidenceRef(), 1, 80, "근거 참조");
        if (!EVIDENCE.matcher(evidenceRef).matches()) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "근거 참조는 TICKET 또는 CHANGE 형식이어야 합니다.");
        }
        String comment = required(request.comment(), 10, 500, "설명");
        String idempotencyKey = required(request.idempotencyKey(), 8, 100, "멱등키");
        Instant expiresAt = request.expiresAt();
        if (expiresAt == null) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "만료 시각은 필수입니다.");
        }
        if (!expiresAt.isAfter(now.plus(Duration.ofMinutes(1)))
                || expiresAt.isAfter(now.plus(MAX_DURATION))) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "만료 시각은 1분 이후부터 30일 이내여야 합니다.");
        }
        return new ValidatedSuppression(ruleKey, clusterId, namespace, workload, executable,
                targetPrefix, operation, reason, evidenceRef, comment, expiresAt, idempotencyKey);
    }

    private static String digest(ValidatedSuppression request) {
        StringBuilder canonical = new StringBuilder();
        for (Object value : new Object[] {request.ruleKey(), request.clusterId(), request.namespace(),
                request.workloadName(), request.processExecutable(), request.targetNamePrefix(),
                request.operation(), request.reasonCode(), request.evidenceRef(), request.comment(),
                request.expiresAt().toString()}) {
            String text = Objects.toString(value, "");
            canonical.append(text.length()).append(':').append(text).append('|');
        }
        return RuntimeHashing.sha256(canonical.toString());
    }

    private static String optional(String value, int max, String name) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String normalized = value.trim();
        if (normalized.length() > max) {
            throw new ApiException(ErrorCode.INVALID_INPUT, name + " 길이가 너무 깁니다.");
        }
        return normalized;
    }

    private static String required(String value, int min, int max, String name) {
        String normalized = optional(value, max, name);
        if (normalized == null || normalized.length() < min) {
            throw new ApiException(ErrorCode.INVALID_INPUT, name + " 값이 올바르지 않습니다.");
        }
        return normalized;
    }

    private record OptionalResult(RuntimeSuppressionResponse response) {
        RuntimeSuppressionResponse required() {
            if (response == null) {
                throw new ApiException(ErrorCode.CONFLICT, "멱등 요청을 확인할 수 없습니다.");
            }
            return response;
        }
    }
}
