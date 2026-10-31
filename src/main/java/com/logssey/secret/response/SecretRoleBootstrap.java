package com.logssey.secret.response;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/** Explicit, one-time grants to existing dashboard accounts. ADMIN alone confers no Secret role. */
@Component
class SecretRoleBootstrap {
    private final JdbcTemplate jdbc;
    private final String securityLogin;
    private final String remediatorLogin;
    private final String remediatorTeam;
    private final String operationsLogin;

    SecretRoleBootstrap(JdbcTemplate jdbc,
                        @Value("${logssey.secret.bootstrap-security-login-id:}") String securityLogin,
                        @Value("${logssey.secret.bootstrap-remediator-login-id:}") String remediatorLogin,
                        @Value("${logssey.secret.bootstrap-remediator-team:}") String remediatorTeam,
                        @Value("${logssey.secret.bootstrap-operations-login-id:}") String operationsLogin) {
        this.jdbc = jdbc;
        this.securityLogin = securityLogin;
        this.remediatorLogin = remediatorLogin;
        this.remediatorTeam = remediatorTeam;
        this.operationsLogin = operationsLogin;
    }

    @EventListener(ApplicationReadyEvent.class)
    @Transactional
    public void grantConfiguredRoles() {
        if (securityLogin.isBlank() && remediatorLogin.isBlank() && remediatorTeam.isBlank()
                && operationsLogin.isBlank()) return;
        if (securityLogin.isBlank() || (!remediatorTeam.isBlank() && remediatorLogin.isBlank())
                || remediatorTeam.length() > 100 || !remediatorTeam.equals(remediatorTeam.trim())) {
            throw new IllegalStateException("Invalid Secret role bootstrap configuration");
        }
        long securityUserId = userId(securityLogin)
                .orElseThrow(() -> new IllegalStateException("Secret security bootstrap account does not exist"));
        Long remediatorUserId = remediatorLogin.isBlank() ? null : userId(remediatorLogin)
                .orElseThrow(() -> new IllegalStateException("Secret remediator bootstrap account does not exist"));
        Long operationsUserId = operationsLogin.isBlank() ? null : userId(operationsLogin)
                .orElseThrow(() -> new IllegalStateException("Secret operations bootstrap account does not exist"));
        grant(securityUserId, "SECURITY", securityUserId);
        if (operationsUserId != null) grant(operationsUserId, "OPERATIONS", securityUserId);
        if (remediatorUserId != null) {
            grant(remediatorUserId, "REMEDIATOR", securityUserId);
            if (!remediatorTeam.isBlank()) {
                jdbc.update("""
                        INSERT INTO secret_team_memberships
                            (user_id, team_name, added_by_user_id)
                        SELECT ?, ?, ? WHERE NOT EXISTS (
                            SELECT 1 FROM secret_team_memberships
                            WHERE user_id = ? AND team_name = ?
                        )
                        ON CONFLICT DO NOTHING
                        """, remediatorUserId, remediatorTeam, securityUserId,
                        remediatorUserId, remediatorTeam);
            }
        }
    }

    private Optional<Long> userId(String loginId) {
        return jdbc.query("SELECT user_id FROM dashboard_users WHERE login_id = ?",
                (rs, row) -> rs.getLong(1), loginId).stream().findFirst();
    }

    private void grant(long userId, String role, long grantorId) {
        // Do not undo a deliberate revocation on a later restart.
        jdbc.update("""
                INSERT INTO secret_role_grants
                    (user_id, role, granted_by_user_id, grant_source)
                SELECT ?, ?, ?, 'BOOTSTRAP' WHERE NOT EXISTS (
                    SELECT 1 FROM secret_role_grants
                    WHERE user_id = ? AND role = ? AND connection_id IS NULL
                )
                ON CONFLICT DO NOTHING
                """, userId, role, grantorId, userId, role);
    }
}
