package com.logssey.iac.finding;

import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class IacFindingRepository {

    private final JdbcTemplate jdbc;

    public IacFindingRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    Optional<Long> adminUserId(String loginId) {
        return jdbc.query("SELECT user_id FROM dashboard_users WHERE login_id = ? AND role = 'ADMIN'",
                (rs, row) -> rs.getLong("user_id"), loginId).stream().findFirst();
    }

    boolean userExists(long userId) {
        return Boolean.TRUE.equals(jdbc.queryForObject(
                "SELECT EXISTS (SELECT 1 FROM dashboard_users WHERE user_id = ?)", Boolean.class, userId));
    }

    Optional<FindingResponse> lock(long findingId) {
        return jdbc.query("""
                SELECT finding_id, status, assignee_user_id, version FROM iac_findings WHERE finding_id = ? FOR UPDATE
                """, (rs, row) -> new FindingResponse(rs.getLong("finding_id"), rs.getString("status"),
                rs.getObject("assignee_user_id", Long.class), rs.getLong("version")), findingId).stream().findFirst();
    }

    void update(long findingId, String status, Long assigneeUserId) {
        jdbc.update("""
                UPDATE iac_findings SET status = ?, assignee_user_id = ?, version = version + 1 WHERE finding_id = ?
                """, status, assigneeUserId, findingId);
    }

    void audit(long actor, long findingId, FindingResponse before, FindingResponse after) {
        jdbc.update("""
                INSERT INTO iac_audit_events (actor_kind, actor_user_id, entity_type, entity_id, event_type, before_safe, after_safe)
                VALUES ('USER', ?, 'FINDING', ?, 'FINDING_UPDATED',
                        jsonb_build_object('status', ?::text, 'assigneeUserId', ?::bigint),
                        jsonb_build_object('status', ?::text, 'assigneeUserId', ?::bigint))
                """, actor, findingId, before.status(), before.assigneeUserId(), after.status(), after.assigneeUserId());
    }
}
