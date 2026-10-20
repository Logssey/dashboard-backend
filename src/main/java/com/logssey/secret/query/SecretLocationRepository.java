package com.logssey.secret.query;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

@Repository
public class SecretLocationRepository {
    private final NamedParameterJdbcTemplate jdbc;
    public SecretLocationRepository(JdbcTemplate jdbc) { this.jdbc = new NamedParameterJdbcTemplate(jdbc); }

    public String safeLocationLabel(Row row) {
        String alias=jdbc.queryForObject("SELECT safe_display_alias FROM secret_connection_scopes WHERE scope_id=:scope",
            Map.of("scope",row.scopeId()),String.class);
        return com.logssey.secret.connection.SecretDisplayLabels.location(alias,row.occurrenceId());
    }

    // The ACL is applied before any grouping, count, timestamp, or validation projection.
    public List<Row> visible(long userId, Long secretId, SecretInventoryFilters filters) {
        return jdbc.query("""
                SELECT c.credential_set_id, c.issuer, c.credential_type, c.component_state, c.masked_label,
                       o.occurrence_id, o.connection_id, o.scope_id, conn.provider AS source, s.response_origin,
                       o.environment, o.exposure_status,
                       CASE WHEN NOT s.enabled THEN 'UNKNOWN'
                            WHEN latest_scope.scope_outcome IN ('PARTIAL','FAILED','SKIPPED','UNKNOWN')
                              AND ((o.presence_status='PRESENT' AND latest_scope.requested_at>o.last_seen_at)
                                OR (o.presence_status='MISSING' AND (o.last_complete_coverage_at IS NULL
                                    OR latest_scope.requested_at>o.last_complete_coverage_at)))
                            THEN 'UNKNOWN' ELSE o.presence_status END AS presence_status,
                       o.first_seen_at, o.last_seen_at,
                       o.last_complete_coverage_at, o.exposure_assessment_version,
                       coalesce((to_jsonb(s)->>'revision')::bigint,s.response_origin_version) AS scope_revision,
                       current_case.case_id, current_case.response_status, current_case.case_version,
                       current_case.assigned_user_id, current_case.assigned_team,
                       CASE WHEN current_case.validation_after_action_at IS NOT NULL AND (latest.provider_checked_at IS NULL OR latest.provider_checked_at<=current_case.validation_after_action_at)
                         THEN 'UNCHECKED' ELSE latest.result END AS validation_result,
                       CASE WHEN current_case.validation_after_action_at IS NOT NULL AND (latest.provider_checked_at IS NULL OR latest.provider_checked_at<=current_case.validation_after_action_at)
                         THEN 'POST_ACTION_VALIDATION_REQUIRED' ELSE latest.reason_code END AS validation_reason,
                       CASE WHEN current_case.validation_after_action_at IS NULL OR latest.provider_checked_at>current_case.validation_after_action_at THEN latest.completed_at END AS validation_at,
                       CASE WHEN current_case.validation_after_action_at IS NULL OR latest.provider_checked_at>current_case.validation_after_action_at THEN latest.provider_checked_at END AS validation_checked_at,
                       policy.policy_result AS storage_policy_result,policy.reason_code AS storage_policy_reason,
                       policy.binding_id AS storage_binding_id,policy.policy_id AS storage_policy_id,
                       policy.policy_version AS storage_policy_version,policy.requires_reassessment,
                       (EXISTS(SELECT 1 FROM secret_current_raw_findings raw WHERE raw.occurrence_id=o.occurrence_id)
                        AND NOT EXISTS(SELECT 1 FROM secret_current_valid_findings valid WHERE valid.occurrence_id=o.occurrence_id))
                           AS all_current_findings_corrected
                FROM secret_occurrences o
                JOIN secret_credential_sets c ON c.credential_set_id=o.credential_set_id
                JOIN secret_connections conn ON conn.connection_id=o.connection_id
                JOIN secret_connection_scopes s ON s.scope_id=o.scope_id AND s.connection_id=o.connection_id
                JOIN secret_occurrence_policy_results policy ON policy.occurrence_id=o.occurrence_id
                LEFT JOIN LATERAL (
                    SELECT outcome.scope_outcome,outcome.requested_at FROM secret_scope_outcomes outcome
                    WHERE outcome.scope_id=s.scope_id AND outcome.scope_revision=s.revision
                      AND outcome.job_kind='FULL_SCAN'
                    ORDER BY outcome.requested_at DESC,outcome.run_id DESC LIMIT 1
                ) latest_scope ON TRUE
                LEFT JOIN LATERAL (
                    SELECT rc.case_id, co.response_status, rc.version AS case_version,co.last_material_action_at,
                           (SELECT max(a.performed_at) FROM secret_action_records a WHERE a.case_id=co.case_id AND a.occurrence_id=co.occurrence_id
                             AND a.action_type IN ('ROTATED','REVOKED','REMOVED_FROM_SOURCE')) AS validation_after_action_at,
                           CASE WHEN jsonb_exists(to_jsonb(co),'assigned_user_id') THEN (to_jsonb(co)->>'assigned_user_id')::bigint
                               ELSE rc.assigned_user_id END AS assigned_user_id,
                           CASE WHEN jsonb_exists(to_jsonb(co),'assigned_team') THEN to_jsonb(co)->>'assigned_team'
                               ELSE rc.assigned_team END AS assigned_team
                    FROM secret_case_occurrences co JOIN secret_response_cases rc ON rc.case_id=co.case_id
                    WHERE co.occurrence_id=o.occurrence_id AND rc.is_current AND rc.case_origin=s.response_origin
                    ORDER BY rc.case_id DESC LIMIT 1
                ) current_case ON TRUE
                LEFT JOIN LATERAL (
                    SELECT v.result,v.reason_code,v.completed_at,v.provider_checked_at
                    FROM secret_validation_attempts v JOIN secret_scan_runs r ON r.run_id=v.run_id
                    WHERE v.credential_set_id=c.credential_set_id AND r.connection_id=o.connection_id
                      AND EXISTS (SELECT 1 FROM secret_run_scopes rs WHERE rs.run_id=r.run_id AND rs.scope_id=o.scope_id)
                      AND EXISTS (SELECT 1 FROM secret_findings f WHERE f.occurrence_id=o.occurrence_id AND f.run_id=v.run_id)
                    ORDER BY v.completed_at DESC,v.attempt_id DESC LIMIT 1
                ) latest ON TRUE
                WHERE (CAST(:secretId AS bigint) IS NULL OR o.credential_set_id=CAST(:secretId AS bigint))
                  AND s.response_origin=:origin
                  AND (:source='ALL' OR conn.provider=:source)
                  AND (:provider='ALL' OR c.issuer=:provider)
                  AND (:environment='ALL' OR o.environment=:environment)
                  AND (:componentState='ALL' OR c.component_state=:componentState)
                  AND (:contentKind='ALL' OR (:contentKind='METADATA' AND c.component_state='METADATA_ONLY')
                       OR (:contentKind='VALUE_FINDINGS' AND c.component_state IN ('CONFIRMED','CANDIDATE')))
                  AND EXISTS (
                    SELECT 1 FROM secret_role_grants g WHERE g.user_id=:userId AND g.revoked_at IS NULL
                    AND (g.connection_id IS NULL OR g.connection_id=o.connection_id)
                    AND (g.role='SECURITY' OR (g.role='REMEDIATOR' AND (
                        current_case.assigned_user_id=:userId OR (current_case.assigned_user_id IS NULL
                        AND current_case.assigned_team IS NOT NULL AND EXISTS (
                            SELECT 1 FROM secret_team_memberships tm WHERE tm.user_id=:userId
                            AND tm.team_name=current_case.assigned_team AND tm.removed_at IS NULL)))))
                  )
                ORDER BY o.last_seen_at DESC,o.credential_set_id DESC,o.occurrence_id
                """, parameters(userId, secretId, filters), (rs, n) -> new Row(
                rs.getLong("credential_set_id"),rs.getString("issuer"),rs.getString("credential_type"),
                rs.getString("component_state"),rs.getString("masked_label"),rs.getLong("occurrence_id"),
                rs.getLong("connection_id"),rs.getLong("scope_id"),rs.getString("source"),rs.getString("response_origin"),
                rs.getString("environment"),rs.getString("exposure_status"),rs.getString("presence_status"),
                rs.getObject("first_seen_at",OffsetDateTime.class),rs.getObject("last_seen_at",OffsetDateTime.class),
                rs.getObject("last_complete_coverage_at",OffsetDateTime.class),rs.getLong("exposure_assessment_version"),
                rs.getLong("scope_revision"),rs.getObject("case_id",Long.class),rs.getString("response_status"),
                rs.getObject("case_version",Long.class),rs.getObject("assigned_user_id",Long.class),
                rs.getString("validation_result"),rs.getString("validation_reason"),
                rs.getObject("validation_at",OffsetDateTime.class),rs.getObject("validation_checked_at",OffsetDateTime.class),
                rs.getString("storage_policy_result"),rs.getString("storage_policy_reason"),
                rs.getObject("storage_binding_id",Long.class),rs.getObject("storage_policy_id",Long.class),
                rs.getObject("storage_policy_version",Long.class),rs.getBoolean("requires_reassessment"),rs.getBoolean("all_current_findings_corrected")));
    }

    private Map<String,Object> parameters(long userId,Long id,SecretInventoryFilters filters) {
        var result=new java.util.HashMap<String,Object>(filters.normalized());
        result.put("userId",userId); result.put("secretId",id); return result;
    }

    public java.util.Set<Long> runOccurrenceIds(long userId,long runId) {
        return new java.util.HashSet<>(jdbc.queryForList("""
            SELECT DISTINCT o.occurrence_id FROM secret_findings f JOIN secret_occurrences o USING(occurrence_id)
            WHERE f.run_id=:run AND
            """+com.logssey.secret.access.SecretOccurrenceAccessSql.predicate("o",":userId"),Map.of("run",runId,"userId",userId),Long.class));
    }

    /** Rows must be the whole authorized key in one origin, before source/environment filters. */
    public boolean retiredHistory(List<Row> rows) {
        if(rows.isEmpty()) return false;
        var first=rows.getFirst();
        if(!java.util.Set.of("PRODUCTION","TEST").contains(first.origin()) || rows.stream().anyMatch(row ->
            row.secretId()!=first.secretId() || !row.origin().equals(first.origin()) || !"CONFIRMED".equals(row.componentState())
            || "UNKNOWN".equals(row.presence()) || row.requiresReassessment() || row.allCurrentFindingsCorrected()
            || (row.caseId()!=null && !"RESOLVED".equals(row.actionStatus()))
            || (row.caseId()==null && !("NORMAL".equals(row.exposure()) && "ALLOWED".equals(row.storagePolicyResult())
                && "PRESENT".equals(row.presence()))))) return false;
        // A proof in another unreadable location/origin must not change this user's classification.
        return Boolean.TRUE.equals(jdbc.queryForObject("""
            SELECT EXISTS(SELECT 1 FROM secret_current_lifecycle_evidence evidence
              WHERE evidence.credential_set_id=:key AND evidence.origin=:origin
                AND evidence.source_occurrence_id IN (:locations)
                AND evidence.verification_level='PROVIDER_VERIFIED' AND evidence.kind IN ('REVOKED','ROTATED','RETIRED'))
            """,Map.of("key",first.secretId(),"origin",first.origin(),
                "locations",rows.stream().map(Row::occurrenceId).distinct().toList()),Boolean.class));
    }

    /** Shared by independent inventory and workbench snapshots, using the same authorized key. */
    public String normalInventorySubtype(List<Row> rows) {
        if(rows.isEmpty() || "UNCLASSIFIED".equals(rows.getFirst().origin())) return null;
        var first=rows.getFirst();
        if(rows.stream().anyMatch(row->row.secretId()!=first.secretId() || !row.origin().equals(first.origin()))) return null;
        if(retiredHistory(rows)) return "RETIRED_HISTORY";
        if(rows.stream().allMatch(row->"METADATA_ONLY".equals(row.componentState()) && row.caseId()==null)) return "METADATA_ONLY";
        if(rows.stream().anyMatch(row->!"CONFIRMED".equals(row.componentState()) || row.caseId()!=null
            || row.requiresReassessment() || row.allCurrentFindingsCorrected() || !"PRESENT".equals(row.presence())
            || !"NORMAL".equals(row.exposure()) || !"ALLOWED".equals(row.storagePolicyResult()))) return null;
        var ids=rows.stream().map(Row::occurrenceId).distinct().toList();
        var current=jdbc.queryForList("SELECT DISTINCT occurrence_id FROM secret_current_valid_findings WHERE occurrence_id IN (:locations)",
            Map.of("locations",ids),Long.class);
        return current.containsAll(ids)?"AUTHORIZED_STORAGE":null;
    }

    public Map<String,Object> iamMetadata(long credentialSetId,List<Long> visibleScopeIds) {
        var rows=jdbc.query("""
                SELECT m.key_status,m.issued_at,m.last_used_at,m.last_used_service,m.last_used_region,m.observed_at
                FROM secret_aws_access_key_observations m
                WHERE m.credential_set_id=:id AND EXISTS (
                    SELECT 1 FROM secret_run_scopes rs WHERE rs.run_id=m.run_id AND rs.scope_id IN (:scopes))
                ORDER BY m.observed_at DESC,m.run_id DESC LIMIT 1
                """,Map.of("id",credentialSetId,"scopes",visibleScopeIds),(rs,n)->
                com.logssey.secret.snapshot.SecretReadSnapshots.facts("keyStatus",rs.getString("key_status"),
                    "issuedAt",rs.getObject("issued_at",OffsetDateTime.class),
                    "lastUsedAt",rs.getObject("last_used_at",OffsetDateTime.class),
                    "lastUsedService",rs.getString("last_used_service"),"lastUsedRegion",rs.getString("last_used_region"),
                    "observedAt",rs.getObject("observed_at",OffsetDateTime.class)));
        return rows.isEmpty()?null:rows.getFirst();
    }

    /** Caller has already applied the shared occurrence ACL. No original path or key identity is loaded. */
    public Map<String,Object> operationalFacts(long occurrenceId) {
        var rows=jdbc.queryForList("""
          SELECT fs.fixture_status,co.last_material_action_at,co.version AS location_version,co.action_cycle,
             (SELECT max(a.performed_at) FROM secret_action_records a WHERE a.case_id=co.case_id AND a.occurrence_id=o.occurrence_id
               AND a.action_type IN ('ROTATED','REVOKED','REMOVED_FROM_SOURCE')) AS validation_after_action_at,
             co.actions_completed_at,v.result AS previous_validation_result,v.reason_code AS previous_validation_reason,
             v.completed_at AS previous_validation_at,v.provider_checked_at AS previous_provider_checked_at
          FROM secret_occurrences o JOIN secret_test_fixture_status fs USING(occurrence_id)
          LEFT JOIN LATERAL(SELECT co.* FROM secret_case_occurrences co JOIN secret_response_cases c USING(case_id)
            JOIN secret_connection_scopes s ON s.scope_id=o.scope_id WHERE co.occurrence_id=o.occurrence_id AND c.is_current
             AND c.case_origin=s.response_origin ORDER BY c.case_id DESC LIMIT 1)co ON true
          LEFT JOIN LATERAL(SELECT v.* FROM secret_validation_attempts v JOIN secret_scan_runs r ON r.run_id=v.run_id
            WHERE v.credential_set_id=o.credential_set_id AND r.connection_id=o.connection_id
             AND EXISTS(SELECT 1 FROM secret_findings f WHERE f.occurrence_id=o.occurrence_id AND f.run_id=v.run_id)
            ORDER BY v.completed_at DESC,v.attempt_id DESC LIMIT 1)v ON true WHERE o.occurrence_id=:id
          """,Map.of("id",occurrenceId));
        return rows.isEmpty()?Map.of():rows.getFirst();
    }

    public record Row(long secretId,String issuer,String credentialType,String componentState,String maskedLabel,
        long occurrenceId,long connectionId,long scopeId,String source,String origin,String environment,String exposure,
        String presence,OffsetDateTime firstSeenAt,OffsetDateTime lastSeenAt,OffsetDateTime lastCompleteCoverageAt,
        long occurrenceVersion,long scopeRevision,Long caseId,String actionStatus,Long caseVersion,Long assignedUserId,
        String validity,String validationReason,OffsetDateTime validationAt,OffsetDateTime validationCheckedAt,
        String storagePolicyResult,String storagePolicyReason,Long storageBindingId,Long storagePolicyId,
        Long storagePolicyVersion,boolean requiresReassessment,boolean allCurrentFindingsCorrected) {}
}
