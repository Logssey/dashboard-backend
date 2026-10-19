package com.logssey.secret.response;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SecretRevalidationService {
    private final SecretCaseRepository cases;
    private final SecretRevalidationRepository repository;
    private final SecretCaseService caseService;

    SecretRevalidationService(SecretCaseRepository cases, SecretRevalidationRepository repository,
                              SecretCaseService caseService) {
        this.cases = cases;
        this.repository = repository;
        this.caseService = caseService;
    }

    @Transactional
    public SecretRevalidationResult request(long caseId, SecretRevalidationRequest request,
                                            String loginId) {
        if (caseId <= 0 || request == null || request.occurrenceId() == null
                || request.occurrenceId() <= 0 || request.expectedVersion() == null
                || request.expectedVersion() < 0 || request.idempotencyKey() == null
                || !request.idempotencyKey().matches("[A-Za-z0-9._:-]{1,120}")) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        long actorId = requireActor(loginId);
        var target = repository.lockTarget(caseId, request.occurrenceId())
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        if (!actorIdEquals(target.assigneeId(), actorId)
                || !cases.hasCaseRole(actorId, caseId, "REMEDIATOR")) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
        String digest = digest(caseId, actorId, request.idempotencyKey());
        var replay = repository.byKey(caseId, digest);
        if (replay.isPresent()) {
            if (replay.get().occurrenceId() != request.occurrenceId()) {
                throw new ApiException(ErrorCode.CONFLICT);
            }
            return replay.get();
        }
        if (target.version() != request.expectedVersion()
                || !"REVIEWED".equals(target.reviewStatus())
                || !"REVALIDATION_PENDING".equals(target.responseStatus())
                || !("REVALIDATION_PENDING".equals(target.stage())
                    || "IN_PROGRESS".equals(target.stage()))
                || !"PRESENT".equals(target.presence())
                || !"GITHUB".equals(target.provider())
                || !"ACTIVE".equals(target.connectionStatus())
                || !target.scopeEnabled()
                || !target.caseOrigin().equals(target.responseOrigin())
                || !SecretGithubScopePolicy.approved(target.contentType(),
                        target.historyLimit(), target.approvedRef())
                || repository.activeJob(target.connectionId())) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        var action = repository.latestAction(caseId, target.occurrenceId())
                .orElseThrow(() -> new ApiException(ErrorCode.CONFLICT));
        var baseline = repository.baseline(target.occurrenceId())
                .orElse(new SecretRevalidationRepository.Baseline(null, null));
        try {
            return repository.reserve(target, action, baseline, actorId, digest);
        } catch (DataIntegrityViolationException conflict) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
    }

    @Transactional(readOnly = true)
    public List<SecretRevalidationResult> list(long caseId, String loginId) {
        long actorId = requireActor(loginId);
        if (caseId <= 0 || !cases.caseExists(caseId)) throw new ApiException(ErrorCode.NOT_FOUND);
        if (!cases.canReadCase(actorId, caseId)) throw new ApiException(ErrorCode.FORBIDDEN);
        return repository.list(caseId);
    }

    @Transactional
    public SecretCaseDetail resolve(long caseId, SecretResolveRequest request, String loginId) {
        if (caseId <= 0 || request == null || request.expectedVersion() == null
                || request.expectedVersion() < 0
                || !"POST_ACTION_REVALIDATION".equals(request.reasonCode())) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        long actorId = requireActor(loginId);
        var target = repository.lockResolutionTarget(caseId)
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        if (!cases.hasCaseRole(actorId, caseId, "SECURITY")) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
        if (target.version() != request.expectedVersion()
                || !"REVIEWED".equals(target.reviewStatus())
                || !"REVALIDATION_PENDING".equals(target.stage())) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        var evidence = repository.resolutionEvidence(caseId);
        if (evidence.isEmpty() || repository.otherAbnormalPresent(caseId)
                || evidence.stream().anyMatch(item -> !sufficient(item))) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        repository.resolve(target, actorId, evidence);
        return caseService.detail(caseId, loginId);
    }

    @Transactional
    public SecretCaseDetail resume(long caseId, SecretResumeRequest request, String loginId) {
        if (caseId <= 0 || request == null || request.occurrenceId() == null
                || request.occurrenceId() <= 0 || request.expectedVersion() == null
                || request.expectedVersion() < 0
                || !"REVALIDATION_PRESENT".equals(request.reasonCode())) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        long actorId = requireActor(loginId);
        var target = repository.lockTarget(caseId, request.occurrenceId())
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        if (!actorIdEquals(target.assigneeId(), actorId)
                || !cases.hasCaseRole(actorId, caseId, "REMEDIATOR")) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
        if (target.version() != request.expectedVersion()
                || !"REVALIDATION_PENDING".equals(target.responseStatus())
                || !("REVALIDATION_PENDING".equals(target.stage())
                    || "IN_PROGRESS".equals(target.stage()))) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        var result = repository.latestForResume(caseId, target.occurrenceId())
                .orElseThrow(() -> new ApiException(ErrorCode.CONFLICT));
        if (!"PRESENT".equals(result.status())
                || result.latestActionId() == null
                || result.actionId() != result.latestActionId()) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        repository.resume(target, actorId, result.revalidationId());
        return caseService.detail(caseId, loginId);
    }

    static boolean sufficient(SecretRevalidationRepository.ResolutionEvidence e) {
        return "REVALIDATION_PENDING".equals(e.responseStatus())
                && "MISSING".equals(e.presence())
                && e.actionId() != null && e.performedAt() != null
                && e.revalidationId() != null && "MISSING".equals(e.revalidationStatus())
                && e.actionId().equals(e.revalidationActionId())
                && e.requestedAt() != null && e.requestedAt().isAfter(e.performedAt())
                && e.finishedAt() != null && e.finishedAt().isAfter(e.performedAt())
                && !e.lastSeenAt().isAfter(e.finishedAt())
                && "SUCCEEDED".equals(e.collectionStatus())
                && ("SUCCEEDED".equals(e.detectionStatus())
                    || "SKIPPED".equals(e.detectionStatus()))
                && e.runScopeVersion() != null
                && e.runScopeVersion() == e.currentScopeVersion()
                && "ACTIVE".equals(e.connectionStatus()) && e.scopeEnabled()
                && e.caseOrigin().equals(e.responseOrigin())
                && SecretGithubScopePolicy.approved(e.contentType(), e.historyLimit(),
                        e.approvedRef());
    }

    private long requireActor(String loginId) {
        return cases.actorId(loginId).orElseThrow(() -> new ApiException(ErrorCode.UNAUTHENTICATED));
    }

    private static boolean actorIdEquals(Long assigned, long actorId) {
        return assigned != null && assigned == actorId;
    }

    private static String digest(long caseId, long actorId, String key) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update(ByteBuffer.allocate(Long.BYTES).putLong(caseId).array());
            sha.update(ByteBuffer.allocate(Long.BYTES).putLong(actorId).array());
            sha.update(key.getBytes(StandardCharsets.UTF_8));
            return "R" + HexFormat.of().formatHex(sha.digest());
        } catch (NoSuchAlgorithmException error) {
            throw new IllegalStateException("IDEMPOTENCY_DIGEST_UNAVAILABLE", error);
        }
    }
}
