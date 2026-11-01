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
        return guide(caseId, loginId, true);
    }

    public SecretGuideResponse readiness(long caseId, String loginId) {
        return guide(caseId, loginId, false);
    }

    private SecretGuideResponse guide(long caseId, String loginId, boolean requested) {
        long actorId = cases.actorId(loginId)
                .orElseThrow(() -> new ApiException(ErrorCode.UNAUTHENTICATED));
        if (caseId <= 0) throw new ApiException(ErrorCode.NOT_FOUND);
        var guideCase = guides.currentCase(caseId)
                .orElseThrow(() -> new ApiException(ErrorCode.NOT_FOUND));
        if (!guides.canRead(actorId, caseId)) throw new ApiException(ErrorCode.FORBIDDEN);
        var context = guideCase.safeContext();
        var fallback = SecretGuideCatalog.fallback(context);
        String reason = eligibilityReason(guideCase, context, actorId, caseId);
        if (!"READY".equals(reason)) {
            return fallback.withReadiness(new SecretGuideReadiness("UNAVAILABLE", reason,
                    false, requested, false, false));
        }
        if (!requested) {
            return fallback.withReadiness(new SecretGuideReadiness("READY", "READY",
                    true, false, false, false));
        }
        try {
            var selection = provider.select(context);
            if (selection == null) {
                return providerFailure(fallback, "PROVIDER_UNAVAILABLE", false, false);
            }
            var selected = SecretGuideCatalog.fromSelectedCodes(selection.codes(), context);
            if (selected.isPresent()) {
                return selected.get().withReadiness(new SecretGuideReadiness("GENERATED",
                        selection.reasonCode(), true, true, selection.providerCalled(), selection.cached()));
            }
            return providerFailure(fallback, selection.codes() == null ? selection.reasonCode()
                    : "PROVIDER_INVALID_RESPONSE", selection.providerCalled(), selection.cached());
        } catch (RuntimeException ignored) {
            return providerFailure(fallback, "PROVIDER_UNAVAILABLE", false, false);
        }
    }

    private String eligibilityReason(SecretGuideRepository.GuideCase guideCase,
                                     SecretGuideContext context, long actorId, long caseId) {
        if (!context.supportedIssuer()) return "UNSUPPORTED_ISSUER";
        if (!"TEST".equals(guideCase.origin())) return "TEST_ONLY";
        if (!guideCase.syntheticFixture()) return "SYNTHETIC_FIXTURE_REQUIRED";
        if (!guides.allLocationsReadable(actorId, caseId)) return "ALL_LOCATIONS_ACCESS_REQUIRED";
        try {
            String reason = provider.configurationReason();
            return reason == null ? "PROVIDER_UNAVAILABLE" : reason;
        } catch (RuntimeException ignored) {
            return "PROVIDER_UNAVAILABLE";
        }
    }

    private static SecretGuideResponse providerFailure(SecretGuideResponse fallback, String reason,
                                                       boolean called, boolean cached) {
        return fallback.withReadiness(new SecretGuideReadiness("FALLBACK", reason,
                true, true, called, cached));
    }
}
