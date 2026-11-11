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
                    WITH locations AS (
                        SELECT co.occurrence_id,co.response_status,observed.result,
                               observed.provider_checked_at,observed.completed_at,action.performed_at
                        FROM secret_case_occurrences co JOIN secret_occurrences o USING(occurrence_id)
                        LEFT JOIN LATERAL (
                            SELECT v.result,v.provider_checked_at,v.completed_at
                            FROM secret_current_validation_attempts v JOIN secret_scan_runs r ON r.run_id=v.run_id
                            WHERE v.occurrence_id=co.occurrence_id AND v.credential_set_id=c.credential_set_id
                              AND r.connection_id=o.connection_id
                              AND EXISTS(SELECT 1 FROM secret_run_scopes rs WHERE rs.run_id=r.run_id AND rs.scope_id=o.scope_id)
                              AND EXISTS(SELECT 1 FROM secret_findings f WHERE f.occurrence_id=co.occurrence_id AND f.run_id=v.run_id)
                            ORDER BY v.completed_at DESC,v.attempt_id DESC LIMIT 1
                        ) observed ON TRUE
                        LEFT JOIN LATERAL (
                            SELECT max(a.performed_at) AS performed_at FROM secret_action_records a
                            WHERE a.case_id=co.case_id AND a.occurrence_id=co.occurrence_id
                              AND a.action_type IN('ROTATED','REVOKED','REMOVED_FROM_SOURCE')
                        ) action ON TRUE
                        WHERE co.case_id=c.case_id
                    ), relevant AS (
                        SELECT * FROM locations WHERE response_status<>'RESOLVED'
                          OR NOT EXISTS(SELECT 1 FROM locations WHERE response_status<>'RESOLVED')
                    ), latest AS (
                        SELECT * FROM relevant WHERE completed_at IS NOT NULL
                        ORDER BY completed_at DESC,occurrence_id DESC LIMIT 1
                    )
                    SELECT CASE
                        WHEN EXISTS(SELECT 1 FROM relevant WHERE performed_at IS NOT NULL
                          AND (provider_checked_at IS NULL OR provider_checked_at<=performed_at)) THEN 'UNCHECKED'
                        WHEN latest.completed_at IS NULL THEN 'UNCHECKED'
                        WHEN latest.result IN('VALID','INVALID') AND
                          (latest.provider_checked_at IS NULL OR latest.provider_checked_at<=clock_timestamp()-interval '6 hours') THEN 'UNKNOWN'
                        ELSE COALESCE(latest.result,'UNCHECKED') END AS result
                    FROM (SELECT 1) seed LEFT JOIN latest ON TRUE
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
