package com.logssey.secret.response;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;

@Service
public class SecretTriageService {
    private final SecretTriageRepository triage;
    private final SecretCaseRepository cases;

    SecretTriageService(SecretTriageRepository triage, SecretCaseRepository cases) {
        this.triage = triage;
        this.cases = cases;
    }

    @Transactional(readOnly = true)
    public SecretTriageCandidateList candidates(int page, int size, String loginId) {
        long actorId = requireSecurityActor(loginId);
        if (page < 0 || page > 1_000_000 || size < 1 || size > 100) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        return new SecretTriageCandidateList(triage.candidates(actorId, size, (long) page * size),
                triage.candidateCount(actorId), page, size);
    }

    @Transactional(readOnly = true)
    public SecretTriageCandidateDetail candidate(long secretId, String loginId) {
        long actorId = requireSecurityActor(loginId);
        if (secretId <= 0) throw new ApiException(ErrorCode.NOT_FOUND);
        return triage.candidate(actorId, secretId)
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
    }

    @Transactional(readOnly = true)
    public SecretScopeOriginResponse scope(long scopeId, String loginId) {
        var scope = triage.scope(scopeId, false).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        requireSecurity(loginId, scope.connectionId());
        if (!scope.activeGithub()) throw new ApiException(ErrorCode.NOT_FOUND);
        return scopeResponse(scope);
    }

    @Transactional
    public SecretScopeOriginResponse classify(long scopeId, SecretScopeOriginRequest request,
                                               String loginId) {
        var scope = triage.scope(scopeId, true).orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        long actorId = requireSecurity(loginId, scope.connectionId());
        if (request == null || request.expectedVersion() == null || request.expectedVersion() < 0
                || !("TEST".equals(request.origin()) && "APPROVED_TEST_FIXTURE".equals(request.reasonCode())
                  || "PRODUCTION".equals(request.origin())
                        && "APPROVED_PRODUCTION_SOURCE".equals(request.reasonCode()))) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        if (!scope.activeGithub() || scope.syntheticFixture() && "PRODUCTION".equals(request.origin())
                || !"UNCLASSIFIED".equals(scope.origin())
                || scope.originVersion() != request.expectedVersion()
                || triage.classify(scopeId, request.expectedVersion(), request.origin(), actorId,
                        request.reasonCode()) != 1) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        return scopeResponse(triage.scope(scopeId, false).orElseThrow());
    }

    @Transactional(readOnly = true)
    public SecretOccurrenceTriageResponse occurrence(long occurrenceId, String loginId) {
        var occurrence = triage.occurrence(occurrenceId, false)
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        requireSecurity(loginId, occurrence.connectionId());
        if (!occurrence.visibleSource()) throw new ApiException(ErrorCode.NOT_FOUND);
        return occurrenceResponse(occurrence);
    }

    @Transactional
    public SecretOccurrenceTriageResponse assess(long occurrenceId,
                                                 SecretExposureAssessmentRequest request,
                                                 String loginId) {
        var occurrence = triage.occurrence(occurrenceId, true)
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        long actorId = requireSecurity(loginId, occurrence.connectionId());
        if (request == null || request.expectedVersion() == null || request.expectedVersion() < 0
                || request.findingId() == null || request.findingId() <= 0
                || !validDecision(request.decision(), request.reasonCode(), occurrence.scopeOrigin())) {
            throw new ApiException(ErrorCode.INVALID_INPUT);
        }
        if (!occurrence.assessable()
                || !triage.hasCurrentOriginDecision(occurrence.scopeId(),
                        occurrence.scopeOriginVersion(), occurrence.scopeOrigin())
                || !triage.latestAssessmentMatches(occurrenceId, occurrence.assessmentVersion(),
                        occurrence.exposureStatus())
                || triage.currentCaseForOccurrence(occurrenceId)
                || occurrence.assessmentVersion() != request.expectedVersion()) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        var finding = triage.finding(request.findingId(), occurrenceId)
                .orElseThrow(() -> new ApiException(ErrorCode.INVALID_INPUT));
        if (request.decision().equals(occurrence.exposureStatus())
                || triage.assess(occurrence, finding, request.decision(), request.reasonCode(), actorId) != 1) {
            throw new ApiException(ErrorCode.CONFLICT);
        }
        return occurrenceResponse(triage.occurrence(occurrenceId, false).orElseThrow());
    }

    private static boolean validDecision(String decision, String reasonCode, String origin) {
        if ("NORMAL".equals(decision)) return "AUTHORIZED_LOCATION".equals(reasonCode);
        if (!"ABNORMAL".equals(decision)) return false;
        return "UNAPPROVED_SOURCE_LOCATION".equals(reasonCode)
                || "TEST".equals(origin) && "SIMULATED_EXPOSURE".equals(reasonCode);
    }

    private long requireSecurity(String loginId, long connectionId) {
        long actorId = requireSecurityActor(loginId);
        if (!cases.hasConnectionRole(actorId, connectionId, "SECURITY")) {
            throw new ApiException(ErrorCode.FORBIDDEN);
        }
        return actorId;
    }

    private long requireSecurityActor(String loginId) {
        long actorId = cases.actorId(loginId)
                .orElseThrow(() -> new ApiException(ErrorCode.UNAUTHENTICATED));
        if (!triage.hasSecurityRole(actorId)) throw new ApiException(ErrorCode.FORBIDDEN);
        return actorId;
    }

    private SecretScopeOriginResponse scopeResponse(SecretTriageRepository.ScopeState scope) {
        return new SecretScopeOriginResponse(scope.scopeId(), scope.connectionId(), scope.scopeKey(),
                scope.origin(), scope.originVersion(), scope.classifiedByUserId(),
                scope.classifiedAt(),
                !scope.activeGithub() || !"UNCLASSIFIED".equals(scope.origin())
                        ? List.of() : scope.syntheticFixture() ? List.of("TEST")
                        : List.of("TEST", "PRODUCTION"),
                triage.scopeHistory(scope.scopeId()));
    }

    private SecretOccurrenceTriageResponse occurrenceResponse(
            SecretTriageRepository.OccurrenceState occurrence) {
        return new SecretOccurrenceTriageResponse(occurrence.occurrenceId(), occurrence.secretId(),
                occurrence.connectionId(), occurrence.scopeId(), occurrence.componentState(),
                occurrence.exposureStatus(), occurrence.presenceStatus(), occurrence.assessmentVersion(),
                occurrence.scopeOrigin(), occurrence.scopeOriginVersion(),
                triage.currentCaseId(occurrence.secretId(), occurrence.scopeOrigin()),
                triage.findings(occurrence.occurrenceId()),
                triage.assessmentHistory(occurrence.occurrenceId()));
    }
}
