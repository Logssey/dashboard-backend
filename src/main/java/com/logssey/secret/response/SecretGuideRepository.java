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
                       EXISTS (SELECT 1 FROM secret_case_occurrences co WHERE co.case_id=c.case_id)
                       AND NOT EXISTS(SELECT 1 FROM secret_case_occurrences co JOIN secret_occurrences o USING(occurrence_id)
                         WHERE co.case_id=c.case_id AND NOT EXISTS(SELECT 1 FROM secret_current_fixture_attestations t
                           WHERE t.credential_set_id=c.credential_set_id AND t.scope_id=o.scope_id))
                       AND NOT EXISTS(SELECT 1 FROM secret_confirmed_real_credentials real WHERE real.credential_set_id=c.credential_set_id) AS synthetic_fixture
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

    boolean canRead(long actor,long caseId) {
        return new org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate(jdbc).queryForObject("""
         SELECT EXISTS(SELECT 1 FROM secret_case_occurrences co JOIN secret_occurrences o USING(occurrence_id)
          WHERE co.case_id=:case AND
         """+com.logssey.secret.access.SecretOccurrenceAccessSql.predicate("o",":actor")+")",java.util.Map.of("case",caseId,"actor",actor),Boolean.class);
    }
    boolean allLocationsReadable(long actor,long caseId) {
        return new org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate(jdbc).queryForObject("""
         SELECT NOT EXISTS(SELECT 1 FROM secret_case_occurrences co JOIN secret_occurrences o USING(occurrence_id)
          WHERE co.case_id=:case AND NOT (
         """+com.logssey.secret.access.SecretOccurrenceAccessSql.predicate("o",":actor")+"))",java.util.Map.of("case",caseId,"actor",actor),Boolean.class);
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
