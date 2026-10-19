package com.logssey.secret.response;

import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

/** Reads only the limited fields needed for a guide; never loads labels, paths, or findings. */
@Repository
class SecretGuideRepository {
    private final JdbcTemplate jdbc;

    SecretGuideRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    Optional<GuideCase> currentCase(long caseId) {
        return jdbc.query("""
                SELECT c.case_origin, c.action_status, c.assigned_user_id,
                       s.issuer, s.credential_type, s.component_state,
                       COALESCE(latest.result, 'UNCHECKED') AS validation_status,
                       EXISTS (SELECT 1 FROM secret_case_occurrences co
                               WHERE co.case_id = c.case_id)
                       AND NOT EXISTS (
                           SELECT 1 FROM secret_case_occurrences co
                           JOIN secret_occurrences o ON o.occurrence_id = co.occurrence_id
                           JOIN secret_connection_scopes scope ON scope.scope_id = o.scope_id
                           JOIN secret_connections conn ON conn.connection_id = o.connection_id
                           WHERE co.case_id = c.case_id
                             AND (scope.content_type <> 'GITHUB_REPOSITORY_FILES'
                                  OR scope.history_limit <> 'CURRENT_COMMIT_ONLY'
                                  OR scope.approved_ref !~* '^github://Logssey/test-find-key/[^/?#]+/([^/?#]+/)+$'
                                  OR scope.response_origin <> 'TEST'
                                  OR NOT scope.enabled
                                  OR conn.status <> 'ACTIVE')
                       ) AS synthetic_fixture
                FROM secret_response_cases c
                JOIN secret_credential_sets s ON s.credential_set_id = c.credential_set_id
                LEFT JOIN LATERAL (
                    SELECT v.result FROM secret_validation_attempts v
                    WHERE v.credential_set_id = s.credential_set_id
                    ORDER BY v.completed_at DESC, v.attempt_id DESC LIMIT 1
                ) latest ON TRUE
                WHERE c.case_id = ? AND c.is_current
                """, (rs, row) -> new GuideCase(rs.getString("case_origin"),
                rs.getString("action_status"),
                rs.getObject("assigned_user_id", Long.class),
                rs.getString("issuer"), rs.getString("credential_type"),
                rs.getString("component_state"), rs.getString("validation_status"),
                rs.getBoolean("synthetic_fixture")),
                caseId).stream().findFirst();
    }

    record GuideCase(String origin, String stage, Long assigneeUserId, String issuer,
                     String credentialType, String componentState, String validationStatus,
                     boolean syntheticFixture) {
        SecretGuideContext safeContext() {
            return SecretGuideContext.of(issuer, credentialType, componentState, stage,
                    validationStatus);
        }
    }
}
