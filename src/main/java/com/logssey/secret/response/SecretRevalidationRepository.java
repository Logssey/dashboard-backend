package com.logssey.secret.response;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
class SecretRevalidationRepository {
    private final JdbcTemplate jdbc;

    SecretRevalidationRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    Optional<Target> lockTarget(long caseId, long occurrenceId) {
        return jdbc.query("""
                SELECT c.case_id, c.version, c.review_status, c.action_status,
                       c.assigned_user_id, c.credential_set_id, c.case_origin,
                       o.occurrence_id, co.response_status, o.connection_id, o.scope_id,
                       o.presence_status, s.fingerprint_key_version,
                       conn.provider, conn.status AS connection_status, conn.scope_version,
                       (scope.enabled AND (scope.content_type<>'GITHUB_REPOSITORY_FILES'
                         OR o.source_context_ref=scope.approved_ref)) AS enabled, scope.content_type, scope.history_limit,
                       scope.approved_ref, scope.response_origin, scope.revision,scope.response_origin_version, co.version AS occurrence_version, co.action_cycle,
                       co.last_material_action_at, co.actions_completed_at
                FROM secret_response_cases c
                JOIN secret_case_occurrences co ON co.case_id = c.case_id
                JOIN secret_occurrences o ON o.occurrence_id = co.occurrence_id
                JOIN secret_credential_sets s ON s.credential_set_id = c.credential_set_id
                JOIN secret_connections conn ON conn.connection_id = o.connection_id
                JOIN secret_connection_scopes scope ON scope.scope_id = o.scope_id
                WHERE c.case_id = ? AND c.is_current AND o.occurrence_id = ?
                FOR UPDATE OF c, co, conn, scope
                """, (rs, row) -> new Target(rs.getLong("case_id"), rs.getLong("version"),
                rs.getString("review_status"), rs.getString("action_status"),
                rs.getObject("assigned_user_id", Long.class), rs.getLong("credential_set_id"),
                rs.getString("case_origin"), rs.getLong("occurrence_id"),
                rs.getString("response_status"),
                rs.getLong("connection_id"), rs.getLong("scope_id"),
                rs.getString("presence_status"), rs.getString("fingerprint_key_version"),
                rs.getString("provider"), rs.getString("connection_status"),
                rs.getLong("scope_version"), rs.getBoolean("enabled"),
                rs.getString("content_type"), rs.getString("history_limit"),
                rs.getString("approved_ref"), rs.getString("response_origin"),rs.getLong("revision"),rs.getLong("response_origin_version"),rs.getLong("occurrence_version"),rs.getLong("action_cycle"),
                rs.getObject("last_material_action_at",OffsetDateTime.class),rs.getObject("actions_completed_at",OffsetDateTime.class)),
                caseId, occurrenceId).stream().findFirst();
    }

    Optional<SecretRevalidationResult> byKey(long caseId, String digest) {
        return jdbc.query(RESULT_SELECT + "WHERE v.case_id = ? AND v.idempotency_digest = ?",
                (rs, row) -> result(rs), caseId, digest).stream().findFirst();
    }

    List<SecretRevalidationResult> list(long caseId) {
        return jdbc.query(RESULT_SELECT + "WHERE v.case_id = ? ORDER BY v.requested_at DESC, v.revalidation_id DESC",
                (rs, row) -> result(rs), caseId);
    }

    boolean activeJob(long connectionId) {
        return Boolean.TRUE.equals(jdbc.queryForObject("""
                SELECT EXISTS (SELECT 1 FROM secret_jobs
                    WHERE connection_id = ? AND kind IN ('FULL_SCAN','REVALIDATE')
                      AND status IN ('PENDING', 'LEASED'))
                """, Boolean.class, connectionId));
    }

    List<Long> requestableOccurrenceIds(long caseId) {
        List<RequestCandidate> candidates = jdbc.query("""
                SELECT o.occurrence_id, o.connection_id, conn.provider, scope.content_type, scope.history_limit,
                       scope.approved_ref
                FROM secret_response_cases c
                JOIN secret_case_occurrences co ON co.case_id = c.case_id
                JOIN secret_occurrences o ON o.occurrence_id = co.occurrence_id
                JOIN secret_connections conn ON conn.connection_id = o.connection_id
                JOIN secret_connection_scopes scope ON scope.scope_id = o.scope_id
                WHERE c.case_id = ? AND c.is_current AND c.review_status = 'REVIEWED'
                  AND c.action_status IN ('IN_PROGRESS', 'REVALIDATION_PENDING')
                  AND co.response_status = 'REVALIDATION_PENDING'
                  AND o.presence_status = 'PRESENT'
                  AND conn.provider IN ('GITHUB','AWS') AND conn.status = 'ACTIVE'
                  AND scope.enabled AND scope.response_origin = c.case_origin
                  AND (scope.content_type<>'GITHUB_REPOSITORY_FILES' OR o.source_context_ref=scope.approved_ref)
                  AND EXISTS (SELECT 1 FROM secret_action_records a
                      WHERE a.case_id = c.case_id AND a.occurrence_id = o.occurrence_id)
                """, (rs, row) -> new RequestCandidate(rs.getLong("occurrence_id"),
                rs.getLong("connection_id"),
                rs.getString("provider"),
                rs.getString("content_type"), rs.getString("history_limit"),
                rs.getString("approved_ref")), caseId);
        return candidates.stream().filter(item ->
                SecretLocationScopePolicy.approved(item.provider(), item.contentType(), item.historyLimit(),
                        item.approvedRef()) && !activeJob(item.connectionId()))
                .map(RequestCandidate::occurrenceId).toList();
    }

    List<Long> resumableOccurrenceIds(long caseId) {
        return jdbc.query("""
                    SELECT co.occurrence_id FROM secret_case_occurrences co
                    JOIN secret_response_cases c ON c.case_id = co.case_id
                    LEFT JOIN LATERAL (
                        SELECT action_id FROM secret_action_records
                        WHERE case_id = co.case_id AND occurrence_id = co.occurrence_id
                        ORDER BY recorded_at DESC, action_id DESC LIMIT 1
                    ) a ON TRUE
                    LEFT JOIN LATERAL (
                        SELECT action_id, status FROM secret_case_revalidations
                        WHERE case_id = co.case_id AND occurrence_id = co.occurrence_id
                        ORDER BY requested_at DESC, revalidation_id DESC LIMIT 1
                    ) v ON TRUE
                    WHERE co.case_id = ? AND c.is_current
                      AND c.action_status IN ('IN_PROGRESS', 'REVALIDATION_PENDING')
                      AND co.response_status = 'REVALIDATION_PENDING'
                      AND v.status = 'PRESENT' AND v.action_id = a.action_id
                """, (rs, row) -> rs.getLong("occurrence_id"), caseId);
    }

    Optional<Action> latestAction(long caseId, long occurrenceId) {
        return jdbc.query("""
                SELECT action_id, performed_at FROM secret_action_records
                WHERE case_id = ? AND occurrence_id = ? AND action_type IN ('ROTATED','REVOKED','REMOVED_FROM_SOURCE')
                  AND action_cycle=(SELECT action_cycle FROM secret_case_occurrences WHERE case_id=secret_action_records.case_id AND occurrence_id=secret_action_records.occurrence_id)
                ORDER BY performed_at DESC, action_id DESC LIMIT 1
                """, (rs, row) -> new Action(rs.getLong("action_id"),
                rs.getObject("performed_at", OffsetDateTime.class)),
                caseId, occurrenceId).stream().findFirst();
    }

    Optional<Baseline> baseline(long occurrenceId) {
        return jdbc.query("""
                SELECT tr.config_hash, tr.engine_version
                FROM secret_occurrences o
                JOIN secret_findings f ON f.occurrence_id = o.occurrence_id
                    AND f.run_id = o.last_seen_run_id
                JOIN secret_tool_runs tr ON tr.tool_run_id = f.tool_run_id
                    AND tr.status IN ('SUCCEEDED','PARTIAL') AND tr.engine = 'GITLEAKS'
                JOIN secret_run_scopes rs ON rs.run_scope_id = tr.run_scope_id
                    AND rs.scope_id = o.scope_id AND rs.run_id=f.run_id
                    AND ((rs.collection_status='SUCCEEDED' AND tr.status='SUCCEEDED') OR
                      (rs.collection_status IN ('SUCCEEDED','PARTIAL') AND o.latest_object_version IS NOT NULL))
                JOIN secret_connection_scopes current_scope ON current_scope.scope_id=o.scope_id AND current_scope.revision=rs.scope_revision
                JOIN secret_scan_runs source_run ON source_run.run_id=f.run_id
                JOIN secret_connections connection ON connection.connection_id=o.connection_id
                    AND source_run.connection_id=connection.connection_id AND source_run.scope_version=connection.scope_version
                JOIN secret_jobs source_job ON source_job.job_id=source_run.job_id AND source_job.status='SUCCEEDED'
                WHERE o.occurrence_id = ? AND current_scope.enabled
                ORDER BY f.detected_at DESC, f.finding_id DESC LIMIT 1
                """, (rs, row) -> new Baseline(rs.getString("config_hash"),
                rs.getString("engine_version")), occurrenceId).stream().findFirst();
    }

    SecretRevalidationResult reserve(Target target, Action action, Baseline baseline,
                                      long actorId, String digest) {
        return reserve(target,action,baseline,actorId,digest,target.version());
    }

    SecretRevalidationResult reserve(Target target,Action action,Baseline baseline,
                                    long actorId,String digest,long caseVersion) {
        OffsetDateTime now = jdbc.queryForObject("SELECT clock_timestamp()", OffsetDateTime.class);
        long jobId = jdbc.queryForObject("""
                INSERT INTO secret_jobs
                    (kind, connection_id, requested_by_user_id, idempotency_key,
                     scheduled_at, available_at, attempt_no, max_attempts, status, created_at)
                VALUES ('REVALIDATE', ?, ?, ?, ?, ?, 0, 3, 'PENDING', ?)
                RETURNING job_id
                """, Long.class, target.connectionId(), actorId, digest, now, now, now);
        long runId = jdbc.queryForObject("""
                INSERT INTO secret_scan_runs
                    (job_id, connection_id, trigger_type, scope_version, scheduled_at,
                     requested_at, collection_status, detection_status, validation_status,
                     result_status, created_at)
                VALUES (?, ?, 'REVALIDATION', ?, ?, ?, 'PENDING', 'PENDING', 'PENDING',
                        'PENDING', ?)
                RETURNING run_id
                """, Long.class, jobId, target.connectionId(), target.scopeVersion(),
                now, now, now);
        jdbc.update("""
                INSERT INTO secret_run_scopes (run_id, scope_id, collection_status)
                VALUES (?, ?, 'PENDING')
                """, runId, target.scopeId());
        long version = caseVersion + 1;
        long id = jdbc.queryForObject("""
                INSERT INTO secret_case_revalidations
                    (case_id, occurrence_id, action_id, connection_id, scope_id,
                     job_id, run_id, requested_by_user_id, idempotency_digest,
                     baseline_config_hash, baseline_engine_version,
                     baseline_fingerprint_version, case_version, requested_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                RETURNING revalidation_id
                """, Long.class, target.caseId(), target.occurrenceId(), action.id(),
                target.connectionId(), target.scopeId(), jobId, runId, actorId,
                digest, baseline.configHash(), baseline.engineVersion(),
                target.fingerprintVersion(), version, now);
        jdbc.update("""
          UPDATE secret_case_revalidations SET scope_revision=?,scope_origin_version=?,action_cycle=?,occurrence_version=?,last_material_action_at=?,actions_completed_at=?,
            baseline_identity=(SELECT fingerprint FROM secret_credential_sets WHERE credential_set_id=?) WHERE revalidation_id=?
          """,target.scopeRevision(),target.scopeOriginVersion(),target.actionCycle(),target.occurrenceVersion()+1,target.lastMaterialActionAt(),target.actionsCompletedAt(),target.credentialId(),id);
        jdbc.update("UPDATE secret_case_occurrences SET version=version+1 WHERE case_id=? AND occurrence_id=?",target.caseId(),target.occurrenceId());
        jdbc.update("""
                UPDATE secret_response_cases SET version = ?, updated_at = ?
                WHERE case_id = ? AND version = ?
                """, version, now, target.caseId(), caseVersion);
        jdbc.update("""
                INSERT INTO secret_audit_events (case_id, event_type, actor_user_id, case_version)
                VALUES (?, 'REVALIDATION_REQUESTED', ?, ?)
                """, target.caseId(), actorId, version);
        return new SecretRevalidationResult(id, target.occurrenceId(), runId,
                "PENDING", "PENDING", null, now, null);
    }

    Optional<ResolutionTarget> lockResolutionTarget(long caseId) {
        return jdbc.query("""
                SELECT case_id, version, review_status, action_status
                FROM secret_response_cases WHERE case_id = ? AND is_current
                FOR UPDATE
                """, (rs, row) -> new ResolutionTarget(rs.getLong("case_id"),
                rs.getLong("version"), rs.getString("review_status"),
                rs.getString("action_status")), caseId).stream().findFirst();
    }

    List<ResolutionEvidence> resolutionEvidence(long caseId) {
        return jdbc.query("""
                SELECT co.occurrence_id, co.response_status, o.presence_status,
                       o.last_seen_at, a.action_id, a.performed_at,
                       v.revalidation_id, v.action_id AS revalidation_action_id,
                       v.status AS revalidation_status,
                       v.requested_at, v.finished_at,
                       r.collection_status, r.detection_status,
                       r.scope_version AS run_scope_version,
                       conn.scope_version AS current_scope_version,
                       conn.status AS connection_status,
                       scope.enabled AS scope_enabled,
                       scope.response_origin, scope.content_type,
                       scope.history_limit, scope.approved_ref,
                       c.case_origin
                FROM secret_case_occurrences co
                JOIN secret_response_cases c ON c.case_id = co.case_id
                JOIN secret_occurrences o ON o.occurrence_id = co.occurrence_id
                JOIN secret_connections conn ON conn.connection_id = o.connection_id
                JOIN secret_connection_scopes scope ON scope.scope_id = o.scope_id
                LEFT JOIN LATERAL (
                    SELECT action_id, performed_at FROM secret_action_records
                    WHERE case_id = co.case_id AND occurrence_id = co.occurrence_id
                    ORDER BY recorded_at DESC, action_id DESC LIMIT 1
                ) a ON TRUE
                LEFT JOIN LATERAL (
                    SELECT revalidation_id, action_id, status, requested_at, finished_at, run_id
                    FROM secret_case_revalidations
                    WHERE case_id = co.case_id AND occurrence_id = co.occurrence_id
                    ORDER BY requested_at DESC, revalidation_id DESC LIMIT 1
                ) v ON TRUE
                LEFT JOIN secret_scan_runs r ON r.run_id = v.run_id
                WHERE co.case_id = ? ORDER BY co.occurrence_id
                """, (rs, row) -> new ResolutionEvidence(rs.getLong("occurrence_id"),
                rs.getString("response_status"), rs.getString("presence_status"),
                rs.getObject("last_seen_at", OffsetDateTime.class),
                rs.getObject("action_id", Long.class),
                rs.getObject("performed_at", OffsetDateTime.class),
                rs.getObject("revalidation_id", Long.class),
                rs.getObject("revalidation_action_id", Long.class),
                rs.getString("revalidation_status"),
                rs.getObject("requested_at", OffsetDateTime.class),
                rs.getObject("finished_at", OffsetDateTime.class),
                rs.getString("collection_status"), rs.getString("detection_status"),
                rs.getObject("run_scope_version", Long.class),
                rs.getLong("current_scope_version"),
                rs.getString("connection_status"), rs.getBoolean("scope_enabled"),
                rs.getString("response_origin"), rs.getString("case_origin"),
                rs.getString("content_type"), rs.getString("history_limit"),
                rs.getString("approved_ref")), caseId);
    }

    boolean otherAbnormalPresent(long caseId) {
        return Boolean.TRUE.equals(jdbc.queryForObject("""
                SELECT EXISTS (
                    SELECT 1 FROM secret_response_cases c
                    JOIN secret_occurrences o ON o.credential_set_id = c.credential_set_id
                    JOIN secret_connection_scopes s ON s.scope_id = o.scope_id
                    WHERE c.case_id = ? AND o.exposure_status = 'ABNORMAL'
                      AND o.presence_status <> 'MISSING'
                      AND s.response_origin = c.case_origin
                )
                """, Boolean.class, caseId));
    }

    Optional<ResumeEvidence> latestForResume(long caseId, long occurrenceId) {
        return jdbc.query("""
                SELECT v.revalidation_id, v.action_id, v.status, a.action_id AS latest_action_id
                FROM secret_case_revalidations v
                LEFT JOIN LATERAL (
                    SELECT action_id FROM secret_action_records
                    WHERE case_id = v.case_id AND occurrence_id = v.occurrence_id AND action_cycle=v.action_cycle AND action_type IN ('ROTATED','REVOKED','REMOVED_FROM_SOURCE')
                    ORDER BY performed_at DESC, action_id DESC LIMIT 1
                ) a ON TRUE
                WHERE v.case_id = ? AND v.occurrence_id = ?
                  AND v.action_cycle=(SELECT action_cycle FROM secret_case_occurrences co WHERE co.case_id=v.case_id AND co.occurrence_id=v.occurrence_id)
                ORDER BY v.requested_at DESC, v.revalidation_id DESC LIMIT 1
                """, (rs, row) -> new ResumeEvidence(rs.getLong("revalidation_id"),
                rs.getLong("action_id"), rs.getString("status"),
                rs.getObject("latest_action_id", Long.class)),
                caseId, occurrenceId).stream().findFirst();
    }

    void resume(Target target, long actorId, long revalidationId) {
        OffsetDateTime now = jdbc.queryForObject("SELECT clock_timestamp()", OffsetDateTime.class);
        long version = target.version() + 1;
        jdbc.update("""
                UPDATE secret_response_cases
                SET action_status = 'IN_PROGRESS', version = ?, updated_at = ?
                WHERE case_id = ? AND version = ?
                """, version, now, target.caseId(), target.version());
        jdbc.update("""
                UPDATE secret_case_occurrences SET response_status = 'IN_PROGRESS',action_cycle=action_cycle+1,version=version+1,last_material_action_at=NULL,actions_completed_at=NULL
                WHERE case_id = ? AND occurrence_id = ?
                """, target.caseId(), target.occurrenceId());
        jdbc.update("""
                INSERT INTO secret_case_resume_events
                    (case_id, occurrence_id, revalidation_id, resumed_by_user_id,
                     case_version, resumed_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """, target.caseId(), target.occurrenceId(), revalidationId,
                actorId, version, now);
        if ("REVALIDATION_PENDING".equals(target.stage())) {
            jdbc.update("""
                    INSERT INTO secret_case_stage_history
                        (case_id, from_status, to_status, reason_code, actor_user_id, case_version)
                    VALUES (?, 'REVALIDATION_PENDING', 'IN_PROGRESS',
                            'REVALIDATION_PRESENT', ?, ?)
                    """, target.caseId(), actorId, version);
        }
        jdbc.update("""
                INSERT INTO secret_audit_events (case_id, event_type, actor_user_id, case_version)
                VALUES (?, 'REVALIDATION_REOPENED', ?, ?)
                """, target.caseId(), actorId, version);
    }

    void resolve(ResolutionTarget target, long actorId, List<ResolutionEvidence> evidence) {
        OffsetDateTime now = jdbc.queryForObject("SELECT clock_timestamp()", OffsetDateTime.class);
        long version = target.version() + 1;
        jdbc.update("""
                UPDATE secret_response_cases SET action_status = 'RESOLVED',
                    resolved_at = ?, updated_at = ?, version = ?
                WHERE case_id = ? AND version = ?
                """, now, now, version, target.caseId(), target.version());
        jdbc.update("""
                UPDATE secret_case_occurrences SET response_status = 'RESOLVED', resolved_at = ?
                WHERE case_id = ?
                """, now, target.caseId());
        jdbc.update("""
                INSERT INTO secret_case_resolutions
                    (case_id, resolved_by_user_id, reason_code, case_version, resolved_at)
                VALUES (?, ?, 'POST_ACTION_REVALIDATION', ?, ?)
                """, target.caseId(), actorId, version, now);
        for (ResolutionEvidence item : evidence) {
            jdbc.update("""
                    INSERT INTO secret_case_resolution_locations
                        (case_id, occurrence_id, revalidation_id)
                    VALUES (?, ?, ?)
                    """, target.caseId(), item.occurrenceId(), item.revalidationId());
        }
        jdbc.update("""
                INSERT INTO secret_case_stage_history
                    (case_id, from_status, to_status, reason_code, actor_user_id, case_version)
                VALUES (?, 'REVALIDATION_PENDING', 'RESOLVED',
                        'POST_ACTION_REVALIDATION', ?, ?)
                """, target.caseId(), actorId, version);
        jdbc.update("""
                INSERT INTO secret_audit_events (case_id, event_type, actor_user_id, case_version)
                VALUES (?, 'CASE_RESOLVED', ?, ?)
                """, target.caseId(), actorId, version);
    }

    private static final String RESULT_SELECT = """
            SELECT v.revalidation_id, v.occurrence_id, v.run_id, j.status AS job_status,
                   v.status, v.failure_code, v.requested_at, v.finished_at
            FROM secret_case_revalidations v
            JOIN secret_jobs j ON j.job_id = v.job_id
            """;

    private static SecretRevalidationResult result(ResultSet rs) throws SQLException {
        return new SecretRevalidationResult(rs.getLong("revalidation_id"),
                rs.getLong("occurrence_id"), rs.getLong("run_id"),
                rs.getString("job_status"), rs.getString("status"),
                rs.getString("failure_code"),
                rs.getObject("requested_at", OffsetDateTime.class),
                rs.getObject("finished_at", OffsetDateTime.class));
    }

    record Target(long caseId, long version, String reviewStatus, String stage,
                  Long assigneeId, long credentialId, String caseOrigin,
                  long occurrenceId, String responseStatus, long connectionId, long scopeId,
                  String presence, String fingerprintVersion,
                  String provider, String connectionStatus, long scopeVersion,
                  boolean scopeEnabled, String contentType, String historyLimit,
                  String approvedRef, String responseOrigin,long scopeRevision,long scopeOriginVersion,long occurrenceVersion,long actionCycle,
                  OffsetDateTime lastMaterialActionAt,OffsetDateTime actionsCompletedAt) {
    }

    record Action(long id, OffsetDateTime performedAt) {
    }

    record Baseline(String configHash, String engineVersion) {
    }

    record RequestCandidate(long occurrenceId, long connectionId, String provider, String contentType,
                            String historyLimit, String approvedRef) {
    }

    record ResolutionTarget(long caseId, long version, String reviewStatus, String stage) {
    }

    record ResumeEvidence(long revalidationId, long actionId, String status,
                          Long latestActionId) {
    }

    record ResolutionEvidence(long occurrenceId, String responseStatus, String presence,
                              OffsetDateTime lastSeenAt, Long actionId, OffsetDateTime performedAt,
                              Long revalidationId, Long revalidationActionId,
                              String revalidationStatus,
                              OffsetDateTime requestedAt, OffsetDateTime finishedAt,
                              String collectionStatus, String detectionStatus,
                              Long runScopeVersion, long currentScopeVersion,
                              String connectionStatus, boolean scopeEnabled,
                              String responseOrigin, String caseOrigin,
                              String contentType, String historyLimit,
                              String approvedRef) {
    }
}
