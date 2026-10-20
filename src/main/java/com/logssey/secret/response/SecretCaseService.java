package com.logssey.secret.response;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.secret.command.SecretCommandExecutor;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SecretCaseService {
    private static final Set<String> ASSIGNMENT_REASONS = Set.of(
            "INITIAL_ASSIGNMENT", "OWNERSHIP_CHANGE", "TEAM_TRANSFER", "UNASSIGNED", "OTHER");
    private static final Set<String> CASE_ORIGINS = Set.of("PRODUCTION", "TEST");
    private static final Set<String> ACTION_TYPES = Set.of(
            "ROTATED", "REVOKED", "REMOVED_FROM_SOURCE", "PERMISSION_REDUCED");
    private static final Pattern EVIDENCE_REF = Pattern.compile(
            "^(TICKET|CHANGE):[A-Z]{2,10}-[1-9][0-9]{0,9}$");
    private final SecretCaseRepository repository;
    private final SecretRevalidationRepository revalidations;

    SecretCaseService(SecretCaseRepository repository) {
        this(repository, null);
    }

    @Autowired
    SecretCaseService(SecretCaseRepository repository,
                      SecretRevalidationRepository revalidations) {
        this.repository = repository;
        this.revalidations = revalidations;
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
                || request.occurrenceId() <= 0 || !"ASSESSED_EXPOSURE".equals(request.reason())
                || request.expectedAssessmentVersion() == null || request.expectedAssessmentVersion() <= 0
                || request.expectedScopeOriginVersion() == null || request.expectedScopeOriginVersion() <= 0) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        var evidence = repository.openingEligibility(secretId, request.occurrenceId())
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        if (!repository.hasConnectionRole(actorId, evidence.connectionId(), "SECURITY")) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
        if (!evidence.eligible()
                || evidence.assessmentVersion() != request.expectedAssessmentVersion()
                || evidence.scopeOriginVersion() != request.expectedScopeOriginVersion()
                || repository.currentCaseExistsForSecret(secretId, evidence.origin())) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        try {
            long caseId = repository.openCase(secretId, request.occurrenceId(), actorId,
                    request.reason(), evidence.origin());
            return detailUnchecked(caseId, actorId);
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
        return detailUnchecked(caseId, actorId);
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
        SecretCommandExecutor.requireExpectedVersion(request.expectedVersion(), before.version());
        if (Objects.equals(before.assigneeTeam(), team)
                && Objects.equals(before.assigneeUserId(), assigneeId)) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        if (repository.updateAssignment(caseId, request.expectedVersion(), team, assigneeId) != 1) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        repository.recordAssignment(caseId, before, team, assigneeId, request.reason(), actorId);
        return detailUnchecked(caseId, actorId);
    }

    @Transactional
    public SecretCaseDetail review(long caseId, SecretCaseReviewRequest request, String loginId) {
        long actorId = requireActor(loginId);
        requireCurrentCase(caseId);
        requireSecurityRole(actorId, caseId);
        if (request == null || invalidVersion(request.expectedVersion())
                || !("CONFIRMED".equals(request.decision())
                     && "EVIDENCE_CONFIRMED".equals(request.reasonCode()))
                   && !("NEEDS_MORE_INFO".equals(request.decision())
                     && "INSUFFICIENT_EVIDENCE".equals(request.reasonCode()))) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        String reviewStatus = "CONFIRMED".equals(request.decision()) ? "REVIEWED" : "UNREVIEWED";
        if (repository.updateReview(caseId, request.expectedVersion(), reviewStatus) != 1) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        repository.recordReview(caseId, request.decision(), request.reasonCode(),
                actorId, request.expectedVersion() + 1);
        return detailUnchecked(caseId, actorId);
    }

    @Transactional
    public SecretCaseDetail start(long caseId, SecretCaseStartRequest request, String loginId) {
        long actorId = requireActor(loginId);
        requireCurrentCase(caseId);
        requireAssignedRemediator(actorId, caseId);
        if (request == null || invalidVersion(request.expectedVersion())
                || !"RESPONSE_STARTED".equals(request.reasonCode())) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        if (repository.updateStage(caseId, request.expectedVersion(), "OPEN", "IN_PROGRESS") != 1) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        repository.startLocations(caseId);
        repository.recordStage(caseId, "OPEN", "IN_PROGRESS", "RESPONSE_STARTED",
                actorId, request.expectedVersion() + 1);
        repository.recordWorkflowAudit(caseId, "RESPONSE_STARTED", actorId,
                request.expectedVersion() + 1);
        return detailUnchecked(caseId, actorId);
    }

    @Transactional
    public SecretCaseDetail checklist(long caseId, long itemId, SecretChecklistRequest request,
                                      String loginId) {
        long actorId = requireActor(loginId);
        requireCurrentCase(caseId);
        requireAssignedRemediator(actorId, caseId);
        if (itemId <= 0 || request == null || request.completed() == null
                || invalidVersion(request.expectedVersion())
                || !"S2_V1".equals(request.guideVersion())
                || request.completed() && !validEvidence(request.evidenceRef())
                || !request.completed() && request.evidenceRef() != null) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        var item = repository.checklistItem(caseId, itemId)
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        if (!request.guideVersion().equals(item.guideVersion())) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        String status = request.completed() ? "DONE" : "TODO";
        if (status.equals(item.status()) && Objects.equals(request.evidenceRef(), item.evidenceRef())) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        if (repository.bumpVersion(caseId, request.expectedVersion()) != 1) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        repository.updateChecklist(itemId, request.completed(), request.evidenceRef(), actorId);
        repository.recordChecklist(caseId, itemId, item.status(), status,
                request.evidenceRef(), actorId, request.expectedVersion() + 1);
        return detailUnchecked(caseId, actorId);
    }

    @Transactional
    public SecretCaseDetail action(long caseId, SecretActionRequest request, String loginId) {
        long actorId = requireActor(loginId);
        requireCurrentCase(caseId);
        requireAssignedRemediator(actorId, caseId);
        if (request == null || invalidVersion(request.expectedVersion())
                || request.actionType() == null || !ACTION_TYPES.contains(request.actionType())
                || request.occurrenceId() == null || request.occurrenceId() <= 0
                || !validEvidence(request.evidenceRef())
                || !validPerformedAt(request.performedAt())) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        // Serialize actions for the same case before updating child occurrences.
        if (repository.lockVersion(caseId) != request.expectedVersion()) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        var before = repository.summary(caseId)
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        if (!"REVIEWED".equals(repository.reviewStatus(caseId))
                || !("OPEN".equals(before.stage()) || "IN_PROGRESS".equals(before.stage()))
                || !repository.actionableOccurrence(caseId, request.occurrenceId())) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        if (repository.actionLocation(caseId, request.occurrenceId()) != 1) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        String next = repository.allLocationsPending(caseId)
                ? "REVALIDATION_PENDING" : "IN_PROGRESS";
        if (repository.updateStage(caseId, request.expectedVersion(), before.stage(), next) != 1) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        long version = request.expectedVersion() + 1;
        repository.recordAction(caseId, request.occurrenceId(), request.actionType(),
                request.performedAt(), request.evidenceRef(), actorId, version);
        if (!before.stage().equals(next)) {
            repository.recordStage(caseId, before.stage(), next,
                    "EXTERNAL_ACTION_RECORDED", actorId, version);
        }
        return detailUnchecked(caseId, actorId);
    }

    private SecretCaseDetail detailUnchecked(long caseId, long actorId) {
        var summary = repository.summary(caseId).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        String reviewStatus = repository.reviewStatus(caseId);
        boolean security = repository.hasCaseRole(actorId, caseId, "SECURITY");
        boolean remediator = repository.assignedRemediator(actorId, caseId);
        boolean reviewed = "REVIEWED".equals(reviewStatus);
        boolean open = "OPEN".equals(summary.stage());
        boolean pending = "REVALIDATION_PENDING".equals(summary.stage());
        Set<Long> requestable = remediator && reviewed && revalidations != null
                ? Set.copyOf(revalidations.requestableOccurrenceIds(caseId)) : Set.of();
        Set<Long> resumable = remediator && revalidations != null
                ? Set.copyOf(revalidations.resumableOccurrenceIds(caseId)) : Set.of();
        boolean canResolve = security && reviewed && pending && revalidations != null
                && !revalidations.otherAbnormalPresent(caseId);
        if (canResolve) {
            var evidence = revalidations.resolutionEvidence(caseId);
            canResolve = !evidence.isEmpty()
                    && evidence.stream().allMatch(SecretRevalidationService::sufficient);
        }
        var capabilities = new SecretCaseCapabilities(
                security && !reviewed && open,
                remediator && reviewed && open,
                remediator && !"RESOLVED".equals(summary.stage()),
                remediator && reviewed && (open || "IN_PROGRESS".equals(summary.stage())),
                !requestable.isEmpty(),
                canResolve,
                !resumable.isEmpty());
        var occurrences = repository.occurrences(caseId).stream()
                .map(item -> new SecretCaseOccurrence(item.occurrenceId(),
                        item.responseStatus(), requestable.contains(item.occurrenceId()),
                        resumable.contains(item.occurrenceId())))
                .toList();
        return SecretCaseDetail.from(summary, repository.openingEvidence(caseId),
                repository.assignmentHistory(caseId), occurrences,
                reviewStatus, repository.reviews(caseId),
                repository.checklist(caseId), repository.checklistHistory(caseId),
                repository.actions(caseId), repository.stageHistory(caseId), capabilities);
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

    private void requireAssignedRemediator(long actorId, long caseId) {
        if (!repository.assignedRemediator(actorId, caseId)) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
    }

    private static boolean invalidVersion(Long version) {
        return version == null || version < 0;
    }

    private static boolean validEvidence(String ref) {
        return ref != null && EVIDENCE_REF.matcher(ref).matches();
    }

    private static boolean validPerformedAt(java.time.OffsetDateTime at) {
        if (at == null) return false;
        Instant time = at.toInstant();
        Instant now = Instant.now();
        return !time.isBefore(now.minus(30, ChronoUnit.DAYS))
                && !time.isAfter(now.plus(5, ChronoUnit.MINUTES));
    }
}
