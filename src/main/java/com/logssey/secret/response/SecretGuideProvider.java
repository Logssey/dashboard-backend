package com.logssey.secret.response;

import java.util.List;
import java.util.Optional;
import java.time.Instant;

/** A provider selects only catalog codes; all displayed wording remains server-authored. */
interface SecretGuideProvider {
    default String configurationReason() { return "READY"; }
    default String providerId() { return "GROQ"; }
    default String modelId() { return null; }

    default Selection select(SecretGuideContext context) {
        return selectSteps(context).map(codes -> new Selection(codes, providerId() + "_GENERATED", true, false))
                .orElseGet(() -> Selection.fallback("PROVIDER_UNAVAILABLE", true));
    }

    Optional<List<String>> selectSteps(SecretGuideContext context);

    record Selection(List<String> codes, String reasonCode, boolean providerCalled, boolean cached,
                     Instant generatedAt) {
        Selection(List<String> codes, String reasonCode, boolean providerCalled, boolean cached) {
            this(codes, reasonCode, providerCalled, cached, codes == null ? null : Instant.now());
        }
        static Selection fallback(String reason, boolean called) {
            return new Selection(null, reason, called, false);
        }

        Selection cachedCopy() {
            return new Selection(codes, codes == null ? reasonCode : "CACHE_HIT", false, true, generatedAt);
        }
    }
}
