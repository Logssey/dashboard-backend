package com.logssey.secret.response;

import java.util.List;
import java.util.Optional;

/** A provider selects only catalog codes; all displayed wording remains server-authored. */
interface SecretGuideProvider {
    default String configurationReason() { return "READY"; }

    default Selection select(SecretGuideContext context) {
        return selectSteps(context).map(codes -> new Selection(codes, "GROQ_GENERATED", true, false))
                .orElseGet(() -> Selection.fallback("PROVIDER_UNAVAILABLE", true));
    }

    Optional<List<String>> selectSteps(SecretGuideContext context);

    record Selection(List<String> codes, String reasonCode, boolean providerCalled, boolean cached) {
        static Selection fallback(String reason, boolean called) {
            return new Selection(null, reason, called, false);
        }

        Selection cachedCopy() {
            return new Selection(codes, codes == null ? reasonCode : "CACHE_HIT", false, true);
        }
    }
}
