package com.logssey.secret.access;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/** Live grants are checked for every request, including requests using an existing session. */
@Service
public class SecretAccessService {
    private final JdbcTemplate jdbc;

    public SecretAccessService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public SecretPrincipal requirePrincipal(String loginId) {
        if (loginId == null || loginId.isBlank()) throw new ApiException(ErrorCode.UNAUTHENTICATED);
        return jdbc.query("SELECT user_id FROM dashboard_users WHERE login_id = ?",
                (rs, row) -> new SecretPrincipal(rs.getLong(1)), loginId).stream().findFirst()
                .orElseThrow(() -> new ApiException(ErrorCode.UNAUTHENTICATED));
    }

    public void requireAnyRole(SecretPrincipal principal) {
        if (!exists("""
                SELECT EXISTS (SELECT 1 FROM secret_role_grants
                    WHERE user_id = ? AND revoked_at IS NULL)
                """, principal.userId())) throw new ApiException(ErrorCode.FORBIDDEN);
    }

    public boolean hasAnyRole(SecretPrincipal principal, java.util.Set<SecretRole> roles) {
        if (roles == null || roles.isEmpty()) return false;
        return jdbc.query("""
                SELECT role FROM secret_role_grants WHERE user_id = ? AND revoked_at IS NULL
                """, (rs, row) -> SecretRole.valueOf(rs.getString(1)), principal.userId()).stream()
                .anyMatch(roles::contains);
    }

    public boolean hasConnectionRole(SecretPrincipal principal, long connectionId, SecretRole role) {
        if (connectionId <= 0) return false;
        return exists("""
                SELECT EXISTS (SELECT 1 FROM secret_role_grants
                    WHERE user_id = ? AND role = ? AND revoked_at IS NULL
                      AND (connection_id IS NULL OR connection_id = ?))
                """, principal.userId(), role.name(), connectionId);
    }

    public void requireConnectionRole(SecretPrincipal principal, long connectionId, SecretRole role) {
        if (!hasConnectionRole(principal, connectionId, role)) throw new ApiException(ErrorCode.FORBIDDEN);
    }

    /** Operations can read connection/run facts, but cannot thereby read credential values or locations. */
    public boolean canReadConnectionFacts(SecretPrincipal principal, long connectionId) {
        return hasConnectionRole(principal, connectionId, SecretRole.SECURITY)
                || hasConnectionRole(principal, connectionId, SecretRole.OPERATIONS);
    }

    public void requireConnectionFactsRead(SecretPrincipal principal, long connectionId) {
        if (!canReadConnectionFacts(principal, connectionId)) throw new ApiException(ErrorCode.NOT_FOUND);
    }

    /** Only a live per-location assignment can grant REMEDIATOR access. */
    public boolean canReadOccurrence(SecretPrincipal principal, long occurrenceId) {
        if (occurrenceId <= 0) return false;
        return Boolean.TRUE.equals(new org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate(jdbc)
            .queryForObject("SELECT EXISTS(SELECT 1 FROM secret_occurrences o WHERE o.occurrence_id=:id AND "
                + SecretOccurrenceAccessSql.predicate("o", ":userId") + ")",
                java.util.Map.of("id", occurrenceId, "userId", principal.userId()), Boolean.class));
    }
    public void requireOccurrenceRead(SecretPrincipal principal, long occurrenceId) {
        if (!canReadOccurrence(principal, occurrenceId)) throw new ApiException(ErrorCode.NOT_FOUND);
    }

    /** For compatibility endpoints that cannot yet return a permission-filtered projection. */
    public void requireGlobalRead(SecretPrincipal principal) {
        if (!hasGlobalRole(principal, SecretRole.SECURITY)) throw new ApiException(ErrorCode.FORBIDDEN);
    }

    public boolean hasGlobalRole(SecretPrincipal principal, SecretRole role) {
        return exists("""
                SELECT EXISTS (SELECT 1 FROM secret_role_grants
                    WHERE user_id = ? AND role = ?
                      AND connection_id IS NULL AND revoked_at IS NULL)
                """, principal.userId(), role.name());
    }

    private boolean exists(String sql, Object... args) {
        return Boolean.TRUE.equals(jdbc.queryForObject(sql, Boolean.class, args));
    }
}
