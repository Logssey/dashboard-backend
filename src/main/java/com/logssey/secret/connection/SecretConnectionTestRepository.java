package com.logssey.secret.connection;

import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import com.logssey.secret.run.AwsScopeSql;

@Repository
class SecretConnectionTestRepository {
    private final JdbcTemplate jdbc;

    SecretConnectionTestRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    Optional<String> actorRole(String loginId) {
        return jdbc.query("SELECT role FROM dashboard_users WHERE login_id = ?",
                (rs, row) -> rs.getString(1), loginId).stream().findFirst();
    }

    Optional<Connection> connection(long connectionId) {
        return jdbc.query("""
                SELECT connection_id, provider, status, auth_ref FROM secret_connections
                WHERE connection_id = ?
                """, (rs, row) -> new Connection(rs.getLong("connection_id"),
                rs.getString("provider"), rs.getString("status"), rs.getString("auth_ref")),
                connectionId).stream().findFirst();
    }

    Optional<Scope> firstEnabledScope(long connectionId) {
        return jdbc.query("""
                SELECT content_type, approved_ref, history_limit
                FROM secret_connection_scopes
                WHERE connection_id = ? AND enabled
                ORDER BY scope_id LIMIT 1
                """, (rs, row) -> new Scope(rs.getString("content_type"),
                rs.getString("approved_ref"), rs.getString("history_limit")),
                connectionId).stream().findFirst();
    }

    AwsScopeSummary awsScopes(long connectionId) {
        String query = """
                SELECT COUNT(*) AS scope_count,
                       COUNT(*) FILTER (WHERE NOT AWS_SCOPE_VALID) AS invalid_count,
                       COUNT(DISTINCT substring(s.approved_ref FROM '^aws://([0-9]{12})/')) AS account_count,
                       MIN(substring(s.approved_ref FROM '^aws://([0-9]{12})/')) AS account_id
                FROM secret_connection_scopes s WHERE s.connection_id = ? AND s.enabled
                """.replace("AWS_SCOPE_VALID", AwsScopeSql.predicate("s"));
        return jdbc.queryForObject(query, (rs, row) -> new AwsScopeSummary(
                rs.getLong("scope_count"), rs.getLong("invalid_count"),
                rs.getLong("account_count"), rs.getString("account_id")), connectionId);
    }

    void recordProbe(long connectionId, String loginId, SecretConnectionTestResponse probe) {
        jdbc.update("""
                INSERT INTO secret_connection_probes
                  (connection_id, actor_user_id, check_kind, status, reason_code, checked_at)
                SELECT ?, user_id, 'IDENTITY_OR_INSTALLATION', ?, ?, ? FROM dashboard_users WHERE login_id=?
                """, connectionId, probe.status(), probe.reasonCode(), probe.checkedAt(), loginId);
    }

    boolean notionScopesSupported(long connectionId) {
        String valid = com.logssey.secret.notion.NotionScopeSql.predicate("s");
        return Boolean.TRUE.equals(jdbc.queryForObject(
                "SELECT EXISTS(SELECT 1 FROM secret_connection_scopes s WHERE s.connection_id=? AND s.enabled)"
                    + " AND NOT EXISTS(SELECT 1 FROM secret_connection_scopes s WHERE s.connection_id=?"
                    + " AND s.enabled AND (" + valid + ") IS NOT TRUE)",
                Boolean.class, connectionId, connectionId));
    }

    record Connection(long id, String provider, String status, String authRef) { }
    record Scope(String contentType, String approvedRef, String historyLimit) { }
    record AwsScopeSummary(long count, long invalidCount, long accountCount, String accountId) { }
}
