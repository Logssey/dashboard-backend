package com.logssey.secret.connection.core;

import org.springframework.jdbc.core.JdbcTemplate;

import java.nio.file.Path;

/**
 * Resolves this connection's immutable version, with explicit compatibility for legacy file
 * configs.
 */
public final class SourceConnectionCredentialResolver {
    private final JdbcTemplate jdbc;
    private final ConnectionCredentialStore store;
    private final long legacyApp;
    private final long legacyInstallation;
    private final String legacyPath;

    public SourceConnectionCredentialResolver(
            JdbcTemplate jdbc,
            ConnectionCredentialStore store,
            long legacyApp,
            long legacyInstallation,
            String legacyPath) {
        this.jdbc = jdbc;
        this.store = store;
        this.legacyApp = legacyApp;
        this.legacyInstallation = legacyInstallation;
        this.legacyPath = legacyPath;
    }

    public boolean storageConfigured() {
        return store != null;
    }

    public boolean legacyConfigured() {
        return legacyApp > 0
                && legacyInstallation > 0
                && legacyPath != null
                && !legacyPath.isBlank();
    }

    public long legacyAppId() {
        return legacyApp;
    }

    public long legacyInstallationId() {
        return legacyInstallation;
    }

    public ConnectionCredentialStore.Reference put(String name, String token, String payload) {
        if (store == null) throw unavailable();
        return store.put(name, token, payload);
    }

    public java.time.Instant scheduleDeletion(String name) {
        if (store == null) throw unavailable();
        return store.scheduleDeletion(name);
    }

    public void restore(String name) {
        if (store == null) throw unavailable();
        store.restore(name);
    }

    public GitHubSourceCredential resolve(long connectionId) {
        return resolve(connectionId, null);
    }

    public GitHubSourceCredential resolve(long connectionId, Long expectedScopeVersion) {
        try {
            var rows =
                    jdbc.queryForList(
                            """
                            SELECT c.auth_ref,c.source_credential_version,c.source_credential_enabled,
                                   v.secret_name,v.secret_version_id,v.app_id,v.installation_id
                            FROM secret_connections c LEFT JOIN secret_source_credential_versions v
                                ON v.connection_id=c.connection_id AND v.version=c.source_credential_version
                            WHERE c.connection_id=? AND c.provider='GITHUB'
                              AND (?::bigint IS NULL OR (c.scope_version=? AND c.status='ACTIVE'))
                            """,
                            connectionId,
                            expectedScopeVersion,
                            expectedScopeVersion);
            if (rows.isEmpty()) throw unavailable();
            var row = rows.getFirst();
            long version = ((Number) row.get("source_credential_version")).longValue();
            if (version == 0
                    && !row.get("auth_ref").toString().startsWith("github-disabled:")
                    && legacyConfigured())
                return GitHubSourceCredential.fromFile(
                        legacyApp, legacyInstallation, Path.of(legacyPath));
            if (!Boolean.TRUE.equals(row.get("source_credential_enabled"))
                    || store == null
                    || !("github-sm:" + connectionId + ":" + version).equals(row.get("auth_ref")))
                throw unavailable();
            var value =
                    GitHubSourceCredential.fromPayload(
                            store.get(
                                    new ConnectionCredentialStore.Reference(
                                            (String) row.get("secret_name"),
                                            (String) row.get("secret_version_id"))));
            if (value.appId() != ((Number) row.get("app_id")).longValue()
                    || value.installationId() != ((Number) row.get("installation_id")).longValue())
                throw unavailable();
            if (expectedScopeVersion != null
                    && !Boolean.TRUE.equals(
                            jdbc.queryForObject(
                                    "SELECT status='ACTIVE' AND scope_version=? AND"
                                        + " source_credential_version=? AND"
                                        + " source_credential_enabled FROM secret_connections WHERE"
                                        + " connection_id=?",
                                    Boolean.class,
                                    expectedScopeVersion,
                                    version,
                                    connectionId))) throw unavailable();
            return value;
        } catch (RuntimeException ignored) {
            throw unavailable();
        }
    }

    private static IllegalStateException unavailable() {
        return new IllegalStateException("SOURCE_CONNECTION_CREDENTIAL_UNAVAILABLE");
    }
}
