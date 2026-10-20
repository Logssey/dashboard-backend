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
                       latest.result AS validation_result, latest.reason_code AS validation_reason,
                       latest.completed_at AS validation_at, latest.provider_checked_at AS validation_checked_at,
                       policy.policy_result AS storage_policy_result,policy.reason_code AS storage_policy_reason,
                       policy.binding_id AS storage_binding_id,policy.policy_id AS storage_policy_id,
                       policy.policy_version AS storage_policy_version,policy.requires_reassessment
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
                    SELECT rc.case_id, co.response_status, rc.version AS case_version,
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
                rs.getObject("storage_policy_version",Long.class),rs.getBoolean("requires_reassessment")));
    }

    private Map<String,Object> parameters(long userId,Long id,SecretInventoryFilters filters) {
        var result=new java.util.HashMap<String,Object>(filters.normalized());
        result.put("userId",userId); result.put("secretId",id); return result;
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

    public record Row(long secretId,String issuer,String credentialType,String componentState,String maskedLabel,
        long occurrenceId,long connectionId,long scopeId,String source,String origin,String environment,String exposure,
        String presence,OffsetDateTime firstSeenAt,OffsetDateTime lastSeenAt,OffsetDateTime lastCompleteCoverageAt,
        long occurrenceVersion,long scopeRevision,Long caseId,String actionStatus,Long caseVersion,Long assignedUserId,
        String validity,String validationReason,OffsetDateTime validationAt,OffsetDateTime validationCheckedAt,
        String storagePolicyResult,String storagePolicyReason,Long storageBindingId,Long storagePolicyId,
        Long storagePolicyVersion,boolean requiresReassessment) {}
}
