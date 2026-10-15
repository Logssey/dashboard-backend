package com.logssey.secret.response;

import java.util.Objects;
import java.util.Set;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SecretCaseService {
    private static final Set<String> ASSIGNMENT_REASONS = Set.of(
            "INITIAL_ASSIGNMENT", "OWNERSHIP_CHANGE", "TEAM_TRANSFER", "UNASSIGNED", "OTHER");
    private static final Set<String> CASE_ORIGINS = Set.of("PRODUCTION", "TEST");
    private final SecretCaseRepository repository;

    SecretCaseService(SecretCaseRepository repository) {
        this.repository = repository;
    }

    @Transactional(readOnly = true)
    public SecretCaseListResponse list(int page, int size, String origin, String loginId) {
        long actorId = requireActor(loginId);
        if (!repository.hasAnySecretRole(actorId)) throw new ApiException(ErrorCode.FORBIDDEN);
        if (page < 0 || page > 1_000_000 || size < 1 || size > 100
                || !CASE_ORIGINS.contains(origin)) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        return new SecretCaseListResponse(repository.listVisible(actorId, origin, size, (long) page * size),
                repository.countVisible(actorId, origin), page, size);
    }

    @Transactional
    public SecretCaseDetail open(long secretId, SecretCaseOpenRequest request, String loginId) {
        long actorId = requireActor(loginId);
        if (secretId <= 0 || request == null || request.occurrenceId() == null
                || request.occurrenceId() <= 0 || !"ASSESSED_EXPOSURE".equals(request.reason())) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        var evidence = repository.openingEligibility(secretId, request.occurrenceId())
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        if (!repository.hasConnectionRole(actorId, evidence.connectionId(), "SECURITY")) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
        if (!evidence.eligible() || repository.currentCaseExistsForSecret(secretId, evidence.origin())) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        try {
            long caseId = repository.openCase(secretId, request.occurrenceId(), actorId,
                    request.reason(), evidence.origin());
            return detailUnchecked(caseId);
        } catch (DataIntegrityViolationException conflict) {
            // The unique current-case constraint also protects concurrent requests.
            throw new ApiException(ErrorCode.CONFLICT);
        }
    }

    @Transactional(readOnly = true)
    public SecretCaseDetail detail(long caseId, String loginId) {
        long actorId = requireActor(loginId);
        requireCurrentCase(caseId);
        if (!repository.canReadCase(actorId, caseId)) throw new ApiException(ErrorCode.FORBIDDEN);
        return detailUnchecked(caseId);
    }

    @Transactional(readOnly = true)
    public SecretAssigneeListResponse assignees(long caseId, String loginId) {
        long actorId = requireActor(loginId);
        requireCurrentCase(caseId);
        requireSecurityRole(actorId, caseId);
        return new SecretAssigneeListResponse(repository.eligibleAssignees(caseId));
    }

    @Transactional
    public SecretCaseDetail assign(long caseId, SecretAssignmentRequest request, String loginId) {
        long actorId = requireActor(loginId);
        requireCurrentCase(caseId);
        requireSecurityRole(actorId, caseId);
        if (request == null || request.expectedVersion() == null || request.expectedVersion() < 0
                || request.reason() == null || !ASSIGNMENT_REASONS.contains(request.reason())) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        String team = request.team();
        if (team != null && (team.isBlank() || team.length() > 100 || !team.equals(team.trim()))) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        Long assigneeId = request.assigneeUserId();
        if (assigneeId != null && assigneeId <= 0) throw new ApiException(ErrorCode.INVALID_INPUT);
        if (assigneeId != null && !repository.hasCaseRole(assigneeId, caseId, "REMEDIATOR")) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        if (team != null && assigneeId != null && !repository.activeTeamMembership(assigneeId, team)) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        if (team != null && assigneeId == null && !repository.eligibleTeam(caseId, team)) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        SecretCaseSummary before = repository.summary(caseId)
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        if (before.version() != request.expectedVersion()) throw new ApiException(ErrorCode.CONFLICT);
        if (Objects.equals(before.assigneeTeam(), team)
                && Objects.equals(before.assigneeUserId(), assigneeId)) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        if (repository.updateAssignment(caseId, request.expectedVersion(), team, assigneeId) != 1) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        repository.recordAssignment(caseId, before, team, assigneeId, request.reason(), actorId);
        return detailUnchecked(caseId);
    }

    private SecretCaseDetail detailUnchecked(long caseId) {
        var summary = repository.summary(caseId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        return SecretCaseDetail.from(summary, repository.openingEvidence(caseId),
                repository.assignmentHistory(caseId));
    }

    private long requireActor(String loginId) {
        return repository.actorId(loginId).orElseThrow(() -> new ApiException(ErrorCode.UNAUTHENTICATED));
    }

    private void requireCurrentCase(long caseId) {
        if (caseId <= 0 || !repository.caseExists(caseId)) throw new ApiException(ErrorCode.NOT_FOUND);
    }

    private void requireSecurityRole(long actorId, long caseId) {
        if (!repository.hasCaseRole(actorId, caseId, "SECURITY")) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
    }
}
