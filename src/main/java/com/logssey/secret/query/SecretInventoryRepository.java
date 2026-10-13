package com.logssey.secret.query;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
class SecretInventoryRepository {
    private static final Set<String> PUBLIC_VALIDATION_REASONS = Set.of(
            "AUTHENTICATED", "INVALID_ACCESS_KEY", "SIGNATURE_AMBIGUOUS",
            "EXPIRED_SESSION", "DISABLED", "INCOMPLETE_PAIR", "MISSING_SESSION_TOKEN",
            "ACCESS_AMBIGUOUS", "RATE_LIMITED", "PROVIDER_UNAVAILABLE", "CLIENT_FAILURE",
            "SYNTHETIC_FIXTURE");
    private final JdbcTemplate jdbc;

    SecretInventoryRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    Optional<String> actorRole(String loginId) {
        return jdbc.query("SELECT role FROM dashboard_users WHERE login_id = ?",
                (rs, row) -> rs.getString("role"), loginId).stream().findFirst();
    }

    long count(String issuer, String componentState) {
        return jdbc.queryForObject("""
                SELECT COUNT(*) FROM secret_credential_sets
                WHERE (? = 'ALL' OR issuer = ?)
                  AND (? = 'ALL' OR component_state = ?)
                """, Long.class, issuer, issuer, componentState, componentState);
    }

    List<SecretSummaryResponse> list(String issuer, String componentState, int size, long offset) {
        return jdbc.query("""
                SELECT c.credential_set_id, c.issuer, c.credential_type, c.component_state,
                       c.masked_label, c.first_seen_at, c.last_seen_at,
                       latest.result AS validation_result, latest.reason_code AS validation_reason,
                       latest.completed_at AS validated_at,
                       latest.provider_checked_at AS validation_checked_at,
                       (SELECT COUNT(*) FROM secret_occurrences o
                        WHERE o.credential_set_id = c.credential_set_id) AS occurrence_count
                FROM secret_credential_sets c
                LEFT JOIN LATERAL (
                    SELECT v.result, v.reason_code, v.completed_at, v.provider_checked_at
                    FROM secret_validation_attempts v
                    WHERE v.credential_set_id = c.credential_set_id
                    ORDER BY v.completed_at DESC, v.attempt_id DESC LIMIT 1
                ) latest ON TRUE
                WHERE (? = 'ALL' OR c.issuer = ?)
                  AND (? = 'ALL' OR c.component_state = ?)
                ORDER BY c.last_seen_at DESC, c.credential_set_id DESC
                LIMIT ? OFFSET ?
                """, (rs, row) -> summary(rs), issuer, issuer, componentState, componentState, size, offset);
    }

    Optional<SecretDetailResponse> detail(long id) {
        return jdbc.query("""
                SELECT c.credential_set_id, c.issuer, c.credential_type, c.component_state,
                       c.masked_label, c.first_seen_at, c.last_seen_at,
                       c.expiry_policy, c.expires_at, c.lifecycle_status,
                       latest.result AS validation_result, latest.reason_code AS validation_reason,
                       latest.completed_at AS validated_at,
                       latest.provider_checked_at AS validation_checked_at,
                       (SELECT COUNT(*) FROM secret_occurrences o
                        WHERE o.credential_set_id = c.credential_set_id) AS occurrence_count
                FROM secret_credential_sets c
                LEFT JOIN LATERAL (
                    SELECT v.result, v.reason_code, v.completed_at, v.provider_checked_at
                    FROM secret_validation_attempts v
                    WHERE v.credential_set_id = c.credential_set_id
                    ORDER BY v.completed_at DESC, v.attempt_id DESC LIMIT 1
                ) latest ON TRUE
                WHERE c.credential_set_id = ?
                """, (rs, row) -> new SecretDetailResponse(
                rs.getLong("credential_set_id"), rs.getString("issuer"),
                rs.getString("credential_type"), rs.getString("component_state"),
                rs.getString("masked_label"), "UNASSESSED",
                validationStatus(rs), safeReason(rs.getString("validation_reason")),
                time(rs, "validated_at"), time(rs, "validation_checked_at"),
                rs.getLong("occurrence_count"), time(rs, "first_seen_at"),
                time(rs, "last_seen_at"), rs.getString("expiry_policy"),
                time(rs, "expires_at"), rs.getString("lifecycle_status"),
                occurrences(id)), id).stream().findFirst();
    }

    List<SecretConnectionResponse> connections() {
        return jdbc.query("""
                SELECT c.connection_id, c.provider, c.display_name, c.status,
                       COUNT(s.scope_id) AS approved_scope_count
                FROM secret_connections c
                JOIN secret_connection_scopes s ON s.connection_id = c.connection_id AND s.enabled
                WHERE c.status = 'ACTIVE' AND c.provider = 'GITHUB'
                GROUP BY c.connection_id, c.provider, c.display_name, c.status
                ORDER BY c.display_name, c.connection_id
                """, (rs, row) -> new SecretConnectionResponse(
                rs.getLong("connection_id"), rs.getString("provider"),
                rs.getString("display_name"), rs.getString("status"),
                rs.getLong("approved_scope_count")));
    }

    private List<SecretOccurrenceResponse> occurrences(long credentialSetId) {
        return jdbc.query("""
                SELECT occurrence_id, connection_id, source_object_ref, location_key,
                       environment, exposure_status, exposure_range, presence_status,
                       first_seen_at, last_seen_at
                FROM secret_occurrences WHERE credential_set_id = ?
                ORDER BY source_object_ref, location_key, occurrence_id
                """, (rs, row) -> new SecretOccurrenceResponse(
                rs.getLong("occurrence_id"), rs.getLong("connection_id"),
                rs.getString("source_object_ref"), rs.getString("location_key"),
                rs.getString("environment"), rs.getString("exposure_status"),
                rs.getString("exposure_range"), rs.getString("presence_status"),
                time(rs, "first_seen_at"), time(rs, "last_seen_at")), credentialSetId);
    }

    private static SecretSummaryResponse summary(ResultSet rs) throws SQLException {
        return new SecretSummaryResponse(rs.getLong("credential_set_id"),
                rs.getString("issuer"), rs.getString("credential_type"),
                rs.getString("component_state"), rs.getString("masked_label"),
                "UNASSESSED", validationStatus(rs), safeReason(rs.getString("validation_reason")),
                time(rs, "validated_at"), time(rs, "validation_checked_at"),
                rs.getLong("occurrence_count"),
                time(rs, "first_seen_at"), time(rs, "last_seen_at"));
    }

    private static String validationStatus(ResultSet rs) throws SQLException {
        String result = rs.getString("validation_result");
        return result == null ? "UNCHECKED" : result;
    }

    private static String safeReason(String reason) {
        if (reason == null) return null;
        return PUBLIC_VALIDATION_REASONS.contains(reason) ? reason : "UNSPECIFIED_REASON";
    }

    private static OffsetDateTime time(ResultSet rs, String column) throws SQLException {
        return rs.getObject(column, OffsetDateTime.class);
    }
}
