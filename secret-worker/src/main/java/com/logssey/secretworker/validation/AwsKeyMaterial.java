package com.logssey.secretworker.validation;

/** Ephemeral AWS credential material. Never include this object in logs or persisted records. */
public final class AwsKeyMaterial {
    private final String accessKeyId;
    private final String secretAccessKey;
    private final String sessionToken;

    public AwsKeyMaterial(String accessKeyId, String secretAccessKey, String sessionToken) {
        this.accessKeyId = accessKeyId;
        this.secretAccessKey = secretAccessKey;
        this.sessionToken = sessionToken;
    }

    String accessKeyId() {
        return accessKeyId;
    }

    String secretAccessKey() {
        return secretAccessKey;
    }

    String sessionToken() {
        return sessionToken;
    }

    boolean isComplete() {
        return hasText(accessKeyId) && hasText(secretAccessKey)
                && (!accessKeyId.startsWith("ASIA") || hasText(sessionToken));
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    @Override
    public String toString() {
        return "AwsKeyMaterial[REDACTED]";
    }
}
