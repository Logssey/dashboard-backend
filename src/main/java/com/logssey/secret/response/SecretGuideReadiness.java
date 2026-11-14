package com.logssey.secret.response;

import java.time.Instant;

/** Public, bounded metadata. Never includes configuration values or provider response text. */
public record SecretGuideReadiness(String status, String reasonCode, boolean aiAvailable,
                                   boolean aiRequested, boolean providerCalled, boolean cached,
                                   String provider, String model, Instant generatedAt) {
    public SecretGuideReadiness(String status, String reasonCode, boolean aiAvailable,
                                boolean aiRequested, boolean providerCalled, boolean cached) {
        this(status, reasonCode, aiAvailable, aiRequested, providerCalled, cached, null, null, null);
    }

    SecretGuideReadiness withProvider(String provider, String model, Instant generatedAt) {
        return new SecretGuideReadiness(status, reasonCode, aiAvailable, aiRequested,
                providerCalled, cached, provider, model, generatedAt);
    }
}
