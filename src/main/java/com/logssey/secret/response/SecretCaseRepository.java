package com.logssey.secret.response;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
class SecretCaseRepository {
    private static final String VISIBLE_CASE = """
            c.is_current AND c.case_origin = ?
            AND EXISTS (SELECT 1 FROM secret_case_occurrences co WHERE co.case_id = c.case_id)
            AND NOT EXISTS (
                SELECT 1 FROM secret_case_occurrences co
                JOIN secret_occurrences o ON o.occurrence_id = co.occurrence_id
                WHERE co.case_id = c.case_id
                  AND NOT EXISTS (
                    SELECT 1 FROM secret_role_grants g
                    WHERE g.user_id = ? AND g.revoked_at IS NULL
                      AND g.role IN ('SECURITY', 'REMEDIATOR', 'OPERATIONS')
                      AND (g.connection_id IS NULL OR g.connection_id = o.connection_id)
                  )
            )
            """;
    private static final String CASE_COLUMNS = """
            c.case_id, c.credential_set_id, COALESCE(s.masked_label, '***') AS masked_label,
            s.issuer, s.credential_type, c.case_origin, c.action_status, c.assigned_team,
            c.assigned_user_id, assignee.display_name AS assignee_display_name,
            c.version, c.opened_at, c.updated_at
            """;
    private static final String CASE_FROM = """
            FROM secret_response_cases c
            JOIN secret_credential_sets s ON s.credential_set_id = c.credential_set_id
            LEFT JOIN dashboard_users assignee ON assignee.user_id = c.assigned_user_id
            """;

    private final JdbcTemplate jdbc;

    SecretCaseRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    Optional<Long> actorId(String loginId) {
        if (loginId == null) return Optional.empty();
        return jdbc.query("SELECT user_id FROM dashboard_users WHERE login_id = ?",
                (rs, row) -> rs.getLong(1), loginId).stream().findFirst();
    }

    boolean hasAnySecretRole(long userId) {
        return Boolean.TRUE.equals(jdbc.queryForObject("""
                SELECT EXISTS (SELECT 1 FROM secret_role_grants
                               WHERE user_id = ? AND revoked_at IS NULL)
                """, Boolean.class, userId));
    }

    boolean caseExists(long caseId) {
        return Boolean.TRUE.equals(jdbc.queryForObject(
                "SELECT EXISTS (SELECT 1 FROM secret_response_cases WHERE case_id = ? AND is_current)",
                Boolean.class, caseId));
    }

    boolean currentCaseExistsForSecret(long secretId, String origin) {
        return Boolean.TRUE.equals(jdbc.queryForObject("""
                SELECT EXISTS (SELECT 1 FROM secret_response_cases
                               WHERE credential_set_id = ? AND case_origin = ? AND is_current)
                """, Boolean.class, secretId, origin));
    }

    boolean hasConnectionRole(long userId, long connectionId, String role) {
        return Boolean.TRUE.equals(jdbc.queryForObject("""
                SELECT EXISTS (SELECT 1 FROM secret_role_grants
                               WHERE user_id = ? AND role = ? AND revoked_at IS NULL
                                 AND (connection_id IS NULL OR connection_id = ?))
                """, Boolean.class, userId, role, connectionId));
    }

    Optional<OpeningEligibility> openingEligibility(long secretId, long occurrenceId) {
        return jdbc.query("""
                SELECT o.connection_id, c.component_state, o.exposure_status,
                       o.presence_status, conn.provider, conn.status AS connection_status,
                       scope.enabled AS scope_enabled, scope.response_origin
                FROM secret_occurrences o
                JOIN secret_credential_sets c ON c.credential_set_id = o.credential_set_id
                JOIN secret_connections conn ON conn.connection_id = o.connection_id
                JOIN secret_connection_scopes scope ON scope.scope_id = o.scope_id
                WHERE o.occurrence_id = ? AND o.credential_set_id = ?
                FOR UPDATE OF o, c, conn, scope
                """, (rs, row) -> new OpeningEligibility(rs.getLong("connection_id"),
                rs.getString("response_origin"),
                "CONFIRMED".equals(rs.getString("component_state"))
                        && "ABNORMAL".equals(rs.getString("exposure_status"))
                        && "PRESENT".equals(rs.getString("presence_status"))
                        && "GITHUB".equals(rs.getString("provider"))
                        && "ACTIVE".equals(rs.getString("connection_status"))
                        && rs.getBoolean("scope_enabled")
                        && !"UNCLASSIFIED".equals(rs.getString("response_origin"))),
                occurrenceId, secretId)
                .stream().findFirst();
    }

    long openCase(long secretId, long occurrenceId, long actorId, String reason, String origin) {
        long caseId = jdbc.queryForObject("""
                INSERT INTO secret_response_cases
                    (credential_set_id, opening_occurrence_id, opened_by_user_id,
                     opening_reason, case_origin)
                VALUES (?, ?, ?, ?, ?) RETURNING case_id
                """, Long.class, secretId, occurrenceId, actorId, reason, origin);
        jdbc.update("""
                INSERT INTO secret_case_occurrences (case_id, occurrence_id, credential_set_id)
                VALUES (?, ?, ?)
                """, caseId, occurrenceId, secretId);
        jdbc.update("""
                INSERT INTO secret_audit_events (case_id, event_type, actor_user_id, case_version)
                VALUES (?, 'CASE_OPENED', ?, 0)
                """, caseId, actorId);
        return caseId;
    }

    boolean hasCaseRole(long userId, long caseId, String role) {
        return Boolean.TRUE.equals(jdbc.queryForObject("""
                SELECT EXISTS (SELECT 1 FROM secret_case_occurrences WHERE case_id = ?)
                   AND NOT EXISTS (
                     SELECT 1 FROM secret_case_occurrences co
                     JOIN secret_occurrences o ON o.occurrence_id = co.occurrence_id
                     WHERE co.case_id = ?
                       AND NOT EXISTS (
                         SELECT 1 FROM secret_role_grants g
                         WHERE g.user_id = ? AND g.role = ? AND g.revoked_at IS NULL
                           AND (g.connection_id IS NULL OR g.connection_id = o.connection_id)
                       )
                   )
                """, Boolean.class, caseId, caseId, userId, role));
    }

    boolean canReadCase(long userId, long caseId) {
        return Boolean.TRUE.equals(jdbc.queryForObject("""
                SELECT EXISTS (SELECT 1 FROM secret_case_occurrences WHERE case_id = ?)
                   AND NOT EXISTS (
                     SELECT 1 FROM secret_case_occurrences co
                     JOIN secret_occurrences o ON o.occurrence_id = co.occurrence_id
                     WHERE co.case_id = ?
                       AND NOT EXISTS (
                         SELECT 1 FROM secret_role_grants g
                         WHERE g.user_id = ? AND g.revoked_at IS NULL
                           AND g.role IN ('SECURITY', 'REMEDIATOR', 'OPERATIONS')
                           AND (g.connection_id IS NULL OR g.connection_id = o.connection_id)
                       )
                   )
                """, Boolean.class, caseId, caseId, userId));
    }

    long countVisible(long actorId, String origin) {
        return jdbc.queryForObject("SELECT COUNT(*) " + CASE_FROM + " WHERE " + VISIBLE_CASE,
                Long.class, origin, actorId);
    }

    List<SecretCaseSummary> listVisible(long actorId, String origin, int size, long offset) {
        return jdbc.query("SELECT " + CASE_COLUMNS + CASE_FROM + " WHERE " + VISIBLE_CASE
                        + " ORDER BY c.updated_at DESC, c.case_id DESC LIMIT ? OFFSET ?",
                (rs, row) -> summary(rs), origin, actorId, size, offset);
    }

    Optional<SecretCaseSummary> summary(long caseId) {
        return jdbc.query("SELECT " + CASE_COLUMNS + CASE_FROM
                        + " WHERE c.case_id = ? AND c.is_current",
                (rs, row) -> summary(rs), caseId).stream().findFirst();
    }

    OpeningEvidence openingEvidence(long caseId) {
        return jdbc.queryForObject("""
                SELECT opening_occurrence_id, opening_reason
                FROM secret_response_cases WHERE case_id = ?
                """, (rs, row) -> new OpeningEvidence(rs.getLong("opening_occurrence_id"),
                rs.getString("opening_reason")), caseId);
    }

    List<SecretAssignmentHistory> assignmentHistory(long caseId) {
        return jdbc.query("""
                SELECT h.changed_at, h.changed_by_user_id, actor.display_name AS actor_name,
                       h.from_team, h.from_user_id, old_user.display_name AS old_name,
                       h.to_team, h.to_user_id, new_user.display_name AS new_name, h.reason
                FROM secret_assignment_history h
                JOIN dashboard_users actor ON actor.user_id = h.changed_by_user_id
                LEFT JOIN dashboard_users old_user ON old_user.user_id = h.from_user_id
                LEFT JOIN dashboard_users new_user ON new_user.user_id = h.to_user_id
                WHERE h.case_id = ?
                ORDER BY h.changed_at DESC, h.assignment_id DESC
                """, (rs, row) -> new SecretAssignmentHistory(
                time(rs, "changed_at"), rs.getLong("changed_by_user_id"),
                rs.getString("actor_name"), rs.getString("from_team"),
                nullableLong(rs, "from_user_id"), rs.getString("old_name"),
                rs.getString("to_team"), nullableLong(rs, "to_user_id"),
                rs.getString("new_name"), rs.getString("reason")), caseId);
    }

    List<SecretAssignee> eligibleAssignees(long caseId) {
        return jdbc.query("""
                SELECT u.user_id, u.display_name, m.team_name
                FROM dashboard_users u
                LEFT JOIN secret_team_memberships m
                  ON m.user_id = u.user_id AND m.removed_at IS NULL
                WHERE EXISTS (
                    SELECT 1 FROM secret_role_grants g
                    WHERE g.user_id = u.user_id AND g.role = 'REMEDIATOR'
                      AND g.revoked_at IS NULL
                )
                  AND NOT EXISTS (
                    SELECT 1 FROM secret_case_occurrences co
                    JOIN secret_occurrences o ON o.occurrence_id = co.occurrence_id
                    WHERE co.case_id = ?
                      AND NOT EXISTS (
                        SELECT 1 FROM secret_role_grants g
                        WHERE g.user_id = u.user_id AND g.role = 'REMEDIATOR'
                          AND g.revoked_at IS NULL
                          AND (g.connection_id IS NULL OR g.connection_id = o.connection_id)
                      )
                  )
                ORDER BY u.display_name, u.user_id, m.team_name
                """, (rs, row) -> new SecretAssignee(rs.getLong("user_id"),
                rs.getString("display_name"), rs.getString("team_name")), caseId);
    }

    boolean activeTeamMembership(long userId, String team) {
        return Boolean.TRUE.equals(jdbc.queryForObject("""
                SELECT EXISTS (SELECT 1 FROM secret_team_memberships
                               WHERE user_id = ? AND team_name = ? AND removed_at IS NULL)
                """, Boolean.class, userId, team));
    }

    boolean eligibleTeam(long caseId, String team) {
        return eligibleAssignees(caseId).stream().anyMatch(item -> team.equals(item.team()));
    }

    int updateAssignment(long caseId, long expectedVersion, String team, Long assigneeUserId) {
        return jdbc.update("""
                UPDATE secret_response_cases
                SET assigned_team = ?, assigned_user_id = ?,
                    version = version + 1, updated_at = CURRENT_TIMESTAMP
                WHERE case_id = ? AND is_current AND version = ?
                """, team, assigneeUserId, caseId, expectedVersion);
    }

    void recordAssignment(long caseId, SecretCaseSummary before, String team,
                          Long assigneeUserId, String reason, long actorId) {
        jdbc.update("""
                INSERT INTO secret_assignment_history
                    (case_id, from_team, to_team, from_user_id, to_user_id,
                     reason, changed_by_user_id, case_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, caseId, before.assigneeTeam(), team, before.assigneeUserId(),
                assigneeUserId, reason, actorId, before.version() + 1);
        jdbc.update("""
                INSERT INTO secret_audit_events (case_id, event_type, actor_user_id, case_version)
                VALUES (?, 'ASSIGNMENT_CHANGED', ?, ?)
                """, caseId, actorId, before.version() + 1);
    }

    private static SecretCaseSummary summary(ResultSet rs) throws SQLException {
        return new SecretCaseSummary(rs.getLong("case_id"), rs.getLong("credential_set_id"),
                rs.getString("masked_label"), rs.getString("issuer"),
                rs.getString("credential_type"), rs.getString("case_origin"),
                rs.getString("action_status"),
                rs.getString("assigned_team"), nullableLong(rs, "assigned_user_id"),
                rs.getString("assignee_display_name"), rs.getLong("version"),
                time(rs, "opened_at"), time(rs, "updated_at"));
    }

    private static Long nullableLong(ResultSet rs, String column) throws SQLException {
        long value = rs.getLong(column);
        return rs.wasNull() ? null : value;
    }

    private static OffsetDateTime time(ResultSet rs, String column) throws SQLException {
        return rs.getObject(column, OffsetDateTime.class);
    }

    record OpeningEligibility(long connectionId, String origin, boolean eligible) {
    }

    record OpeningEvidence(long occurrenceId, String reason) {
    }
}
