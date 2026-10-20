package com.logssey.secret.access;

/** A resolved dashboard identity. Never infer Secret authority from its login role. */
public record SecretPrincipal(long userId) {
    public SecretPrincipal {
        if (userId <= 0) throw new IllegalArgumentException("Invalid Secret principal");
    }
}
