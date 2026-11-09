package com.logssey.secret.response;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
class SecretTriageRepository {
    private static final String VISIBLE_OCCURRENCE = """
            JOIN secret_connections conn ON conn.connection_id = o.connection_id
            JOIN secret_connection_scopes scope ON scope.scope_id = o.scope_id
            WHERE conn.status = 'ACTIVE' AND scope.enabled
              AND ((conn.provider = 'GITHUB' AND scope.content_type = 'GITHUB_REPOSITORY_FILES'
                AND scope.history_limit = 'CURRENT_COMMIT_ONLY'
                AND scope.approved_ref ~ '^github://[A-Za-z0-9-]{1,39}/[A-Za-z0-9_.-]{1,100}/[^/?#]+/([^/?#]+/)+$')
                OR (conn.provider = 'NOTION' AND scope.content_type = 'NOTION_PAGE_CONTENT'
                AND scope.history_limit = 'CURRENT_VERSION_ONLY'
                AND scope.approved_ref ~ '^notion://pages/([0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$'))
              AND EXISTS (SELECT 1 FROM secret_role_grants g
                          WHERE g.user_id = ? AND g.role = 'SECURITY'
                            AND g.revoked_at IS NULL
                            AND (g.connection_id IS NULL OR g.connection_id = o.connection_id))
            """;
    private final JdbcTemplate jdbc;

    SecretTriageRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    boolean hasSecurityRole(long userId) {
        return Boolean.TRUE.equals(jdbc.queryForObject("""
                SELECT EXISTS (SELECT 1 FROM secret_role_grants
                               WHERE user_id = ? AND role = 'SECURITY' AND revoked_at IS NULL)
                """, Boolean.class, userId));
    }

    long candidateCount(long userId) {
        return jdbc.queryForObject("""
                SELECT COUNT(DISTINCT o.credential_set_id)
                FROM secret_occurrences o
                """ + VISIBLE_OCCURRENCE, Long.class, userId);
    }

    List<SecretTriageCandidate> candidates(long userId, int size, long offset) {
        return jdbc.query("""
                SELECT c.credential_set_id, c.masked_label, c.issuer, c.credential_type,
                       c.component_state, COUNT(*) AS occurrence_count
                FROM secret_occurrences o
                JOIN secret_credential_sets c ON c.credential_set_id = o.credential_set_id
                """ + VISIBLE_OCCURRENCE + """
                GROUP BY c.credential_set_id
                ORDER BY c.credential_set_id DESC LIMIT ? OFFSET ?
                """, (rs, row) -> new SecretTriageCandidate(rs.getLong("credential_set_id"),
                rs.getString("masked_label"), rs.getString("issuer"),
                rs.getString("credential_type"), rs.getString("component_state"),
                rs.getLong("occurrence_count")), userId, size, offset);
    }

    Optional<SecretTriageCandidateDetail> candidate(long userId, long secretId) {
        var items = jdbc.query("""
                SELECT c.credential_set_id, c.masked_label, c.issuer, c.credential_type,
                       c.component_state
                FROM secret_credential_sets c
                WHERE c.credential_set_id = ?
                  AND EXISTS (SELECT 1 FROM secret_occurrences o
                """ + VISIBLE_OCCURRENCE + " AND o.credential_set_id = c.credential_set_id)",
                (rs, row) -> new SecretTriageCandidateDetail(
                rs.getLong("credential_set_id"), rs.getString("masked_label"),
                rs.getString("issuer"), rs.getString("credential_type"),
                rs.getString("component_state"), candidateOccurrences(userId, secretId)),
                secretId, userId);
        return items.stream().findFirst();
    }

    private List<SecretTriageCandidateOccurrence> candidateOccurrences(long userId, long secretId) {
        return jdbc.query("""
                SELECT o.occurrence_id, o.connection_id, o.scope_id,
                       o.source_object_ref, o.location_key, o.environment,
                       o.exposure_status, o.presence_status, o.exposure_assessment_version,
                       scope.response_origin, scope.response_origin_version
                FROM secret_occurrences o
                """ + VISIBLE_OCCURRENCE + """
                AND o.credential_set_id = ?
                ORDER BY o.occurrence_id
                """, (rs, row) -> new SecretTriageCandidateOccurrence(
                rs.getLong("occurrence_id"), rs.getLong("connection_id"), rs.getLong("scope_id"),
                rs.getString("source_object_ref"), rs.getString("location_key"),
                rs.getString("environment"), rs.getString("exposure_status"),
                rs.getString("presence_status"), rs.getLong("exposure_assessment_version"),
                rs.getString("response_origin"), rs.getLong("response_origin_version")),
                userId, secretId);
    }

    Optional<ScopeState> scope(long scopeId, boolean lock) {
        String sql = """
                SELECT scope.scope_id, scope.connection_id, scope.scope_key,
                       scope.response_origin, scope.response_origin_version,
                       scope.response_origin_set_by_user_id, scope.response_origin_set_at,
                       scope.enabled, conn.provider, conn.status AS connection_status,
                       scope.content_type, scope.history_limit, scope.approved_ref
                FROM secret_connection_scopes scope
                JOIN secret_connections conn ON conn.connection_id = scope.connection_id
                WHERE scope.scope_id = ?
                """ + (lock ? " FOR UPDATE OF scope, conn" : "");
        return jdbc.query(sql, (rs, row) -> new ScopeState(
                rs.getLong("scope_id"), rs.getLong("connection_id"), rs.getString("scope_key"),
                rs.getString("response_origin"), rs.getLong("response_origin_version"),
                nullableLong(rs, "response_origin_set_by_user_id"),
                rs.getObject("response_origin_set_at", OffsetDateTime.class), rs.getBoolean("enabled"),
                rs.getString("provider"), rs.getString("connection_status"),
                SecretLocationScopePolicy.approved(rs.getString("provider"),rs.getString("content_type"),
                        rs.getString("history_limit"), rs.getString("approved_ref")),
                SecretGithubScopePolicy.syntheticFixture(rs.getString("approved_ref"))), scopeId)
                .stream().findFirst();
    }

    List<SecretScopeOriginDecision> scopeHistory(long scopeId) {
        return jdbc.query("""
                SELECT from_origin, to_origin, reason_code, actor_user_id, decided_at, version
                FROM secret_scope_origin_decisions WHERE scope_id = ? ORDER BY version DESC
                """, (rs, row) -> new SecretScopeOriginDecision(rs.getString("from_origin"),
                rs.getString("to_origin"), rs.getString("reason_code"), rs.getLong("actor_user_id"),
                rs.getObject("decided_at", OffsetDateTime.class), rs.getLong("version")), scopeId);
    }

    int classify(long scopeId, long expectedVersion, String origin, long actorId, String reasonCode) {
        int updated = jdbc.update("""
                UPDATE secret_connection_scopes
                SET response_origin = ?, response_origin_version = response_origin_version + 1,
                    response_origin_set_by_user_id = ?, response_origin_set_at = CURRENT_TIMESTAMP
                WHERE scope_id = ? AND response_origin = 'UNCLASSIFIED' AND response_origin_version = ?
                """, origin, actorId, scopeId, expectedVersion);
        if (updated == 1) {
            jdbc.update("""
                    INSERT INTO secret_scope_origin_decisions
                        (scope_id, from_origin, to_origin, reason_code, actor_user_id, version)
                    VALUES (?, 'UNCLASSIFIED', ?, ?, ?, ?)
                    """, scopeId, origin, reasonCode, actorId, expectedVersion + 1);
        }
        return updated;
    }

    Optional<OccurrenceState> occurrence(long occurrenceId, boolean lock) {
        String sql = """
                SELECT o.occurrence_id, o.credential_set_id, o.connection_id, o.scope_id,
                       o.exposure_status, o.presence_status, o.exposure_assessment_version,
                       c.component_state, conn.provider, conn.status AS connection_status,
                       scope.enabled AS scope_enabled, scope.response_origin,
                       scope.response_origin_version, scope.content_type,
                       scope.history_limit, scope.approved_ref
                FROM secret_occurrences o
                JOIN secret_credential_sets c ON c.credential_set_id = o.credential_set_id
                JOIN secret_connections conn ON conn.connection_id = o.connection_id
                JOIN secret_connection_scopes scope ON scope.scope_id = o.scope_id
                WHERE o.occurrence_id = ?
                """ + (lock ? " FOR UPDATE OF o, c, conn, scope" : "");
        return jdbc.query(sql, (rs, row) -> new OccurrenceState(
                rs.getLong("occurrence_id"), rs.getLong("credential_set_id"),
                rs.getLong("connection_id"), rs.getLong("scope_id"),
                rs.getString("exposure_status"), rs.getString("presence_status"),
                rs.getLong("exposure_assessment_version"), rs.getString("component_state"),
                rs.getString("provider"), rs.getString("connection_status"),
                rs.getBoolean("scope_enabled"), rs.getString("response_origin"),
                rs.getLong("response_origin_version"),
                SecretLocationScopePolicy.approved(rs.getString("provider"),rs.getString("content_type"),
                        rs.getString("history_limit"), rs.getString("approved_ref"))),
                occurrenceId).stream().findFirst();
    }

    Optional<FindingSnapshot> finding(long findingId, long occurrenceId) {
        return jdbc.query("""
                SELECT finding_id, rule_id, run_id
                FROM secret_findings WHERE finding_id = ? AND occurrence_id = ?
                """, (rs, row) -> new FindingSnapshot(rs.getLong("finding_id"),
                rs.getString("rule_id"), rs.getLong("run_id")), findingId, occurrenceId)
                .stream().findFirst();
    }

    List<SecretTriageFinding> findings(long occurrenceId) {
        return jdbc.query("""
                SELECT finding_id, rule_id, detected_at
                FROM secret_findings WHERE occurrence_id = ?
                ORDER BY detected_at DESC, finding_id DESC LIMIT 100
                """, (rs, row) -> new SecretTriageFinding(rs.getLong("finding_id"),
                rs.getString("rule_id"),
                rs.getObject("detected_at", OffsetDateTime.class)), occurrenceId);
    }

    List<SecretExposureAssessment> assessmentHistory(long occurrenceId) {
        return jdbc.query("""
                SELECT assessment_id, from_status, decision, reason_code, finding_id,
                       finding_rule_id, actor_user_id, assessed_at, version
                FROM secret_exposure_assessments WHERE occurrence_id = ? ORDER BY version DESC
                """, (rs, row) -> new SecretExposureAssessment(rs.getLong("assessment_id"),
                rs.getString("from_status"), rs.getString("decision"), rs.getString("reason_code"),
                rs.getLong("finding_id"), rs.getString("finding_rule_id"),
                rs.getLong("actor_user_id"), rs.getObject("assessed_at", OffsetDateTime.class),
                rs.getLong("version")), occurrenceId);
    }

    boolean currentCaseForOccurrence(long occurrenceId) {
        return Boolean.TRUE.equals(jdbc.queryForObject("""
                SELECT EXISTS (
                    SELECT 1 FROM secret_case_occurrences co
                    JOIN secret_response_cases c ON c.case_id = co.case_id
                    WHERE co.occurrence_id = ? AND c.is_current
                )
                """, Boolean.class, occurrenceId));
    }

    Long currentCaseId(long secretId, String origin) {
        if ("UNCLASSIFIED".equals(origin)) return null;
        return jdbc.query("""
                SELECT case_id FROM secret_response_cases
                WHERE credential_set_id = ? AND case_origin = ? AND is_current
                """, (rs, row) -> rs.getLong("case_id"), secretId, origin)
                .stream().findFirst().orElse(null);
    }

    int assess(OccurrenceState before, FindingSnapshot finding, String decision,
               String reasonCode, long actorId) {
        int updated = jdbc.update("""
                UPDATE secret_occurrences
                SET exposure_status = ?, exposure_assessment_version = exposure_assessment_version + 1
                WHERE occurrence_id = ? AND exposure_assessment_version = ? AND exposure_status = ?
                """, decision, before.occurrenceId(), before.assessmentVersion(), before.exposureStatus());
        if (updated == 1) {
            jdbc.update("""
                    INSERT INTO secret_exposure_assessments
                        (occurrence_id, finding_id, finding_rule_id, finding_run_id,
                         from_status, decision, reason_code, scope_origin, actor_user_id, version)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, before.occurrenceId(), finding.findingId(), finding.ruleId(), finding.runId(),
                    before.exposureStatus(), decision, reasonCode, before.scopeOrigin(), actorId,
                    before.assessmentVersion() + 1);
        }
        return updated;
    }

    boolean hasCurrentOriginDecision(long scopeId, long version, String origin) {
        return Boolean.TRUE.equals(jdbc.queryForObject("""
                SELECT EXISTS (SELECT 1 FROM secret_scope_origin_decisions
                               WHERE scope_id = ? AND version = ? AND to_origin = ?)
                """, Boolean.class, scopeId, version, origin));
    }

    boolean latestAssessmentMatches(long occurrenceId, long version, String status) {
        if (version == 0) return "UNKNOWN".equals(status);
        return Boolean.TRUE.equals(jdbc.queryForObject("""
                SELECT EXISTS (SELECT 1 FROM secret_exposure_assessments
                               WHERE occurrence_id = ? AND version = ? AND decision = ?)
                """, Boolean.class, occurrenceId, version, status));
    }

    private static Long nullableLong(ResultSet rs, String column) throws SQLException {
        long value = rs.getLong(column);
        return rs.wasNull() ? null : value;
    }

    record ScopeState(long scopeId, long connectionId, String scopeKey, String origin,
                      long originVersion, Long classifiedByUserId, OffsetDateTime classifiedAt,
                      boolean enabled, String provider, String connectionStatus,
                      boolean approved,
                      boolean syntheticFixture) {
        boolean activeGithub() {
            return enabled && java.util.Set.of("GITHUB","NOTION").contains(provider) && "ACTIVE".equals(connectionStatus)
                    && approved;
        }
    }

    record OccurrenceState(long occurrenceId, long secretId, long connectionId, long scopeId,
                           String exposureStatus, String presenceStatus, long assessmentVersion,
                           String componentState, String provider, String connectionStatus,
                           boolean scopeEnabled, String scopeOrigin, long scopeOriginVersion,
                           boolean approvedScope) {
        boolean visibleSource() {
            return java.util.Set.of("GITHUB","NOTION").contains(provider) && "ACTIVE".equals(connectionStatus)
                    && scopeEnabled && approvedScope;
        }

        boolean assessable() {
            return visibleSource() && "CONFIRMED".equals(componentState)
                    && "PRESENT".equals(presenceStatus)
                    && !"UNCLASSIFIED".equals(scopeOrigin);
        }
    }

    record FindingSnapshot(long findingId, String ruleId, long runId) {
    }
}
