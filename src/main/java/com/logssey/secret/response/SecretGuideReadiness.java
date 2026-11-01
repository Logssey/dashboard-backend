package com.logssey.secret.response;

/** Public, bounded metadata. Never includes configuration values or provider response text. */
public record SecretGuideReadiness(String status, String reasonCode, boolean aiAvailable,
                                   boolean aiRequested, boolean providerCalled, boolean cached) {
}
