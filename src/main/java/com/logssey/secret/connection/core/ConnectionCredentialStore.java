package com.logssey.secret.connection.core;

/** Immutable remote versions let failed DB commits keep using the previous credential. */
public interface ConnectionCredentialStore extends AutoCloseable {
    record Reference(String secretName, String versionId) {}

    Reference put(String name, String requestToken, String payload);

    String get(Reference reference);

    java.time.Instant scheduleDeletion(String secretName);

    void restore(String secretName);

    @Override
    default void close() {}
}
