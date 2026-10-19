package com.logssey.secret.response;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import org.springframework.stereotype.Service;

/** Read-only guidance, independent of case state transitions and external key changes. */
@Service
public class SecretGuideService {
    private final SecretCaseRepository cases;
    private final SecretGuideRepository guides;
    private final SecretGuideProvider provider;

    SecretGuideService(SecretCaseRepository cases, SecretGuideRepository guides,
                       SecretGuideProvider provider) {
        this.cases = cases;
        this.guides = guides;
        this.provider = provider;
    }

    public SecretGuideResponse guide(long caseId, String loginId) {
        long actorId = cases.actorId(loginId)
                .orElseThrow(() -> new ApiException(ErrorCode.UNAUTHENTICATED));
        if (caseId <= 0) throw new ApiException(ErrorCode.NOT_FOUND);
        var guideCase = guides.currentCase(caseId)
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        boolean security = cases.hasCaseRole(actorId, caseId, "SECURITY");
        boolean assignedRemediator = guideCase.assigneeUserId() != null
                && guideCase.assigneeUserId() == actorId
                && cases.hasCaseRole(actorId, caseId, "REMEDIATOR");
        if (!security && !assignedRemediator) throw new ApiException(ErrorCode.FORBIDDEN);

        // ADR-S009 limits initial external experiments to the approved synthetic fixture.
        if (!"TEST".equals(guideCase.origin()) || !guideCase.syntheticFixture()) {
            return SecretGuideCatalog.fallback();
        }
        try {
            return provider.selectSteps(guideCase.safeContext())
                    .flatMap(SecretGuideCatalog::fromSelectedCodes)
                    .orElseGet(SecretGuideCatalog::fallback);
        } catch (RuntimeException ignored) {
            return SecretGuideCatalog.fallback();
        }
    }
}
