package com.logssey.secret.closure;

import java.time.OffsetDateTime;
import java.util.*;
import com.logssey.common.error.*;
import com.logssey.secret.access.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import static com.logssey.secret.evidence.SecretEvidenceRules.*;

@Repository
class SecretClosureRepository {
    private final JdbcTemplate jdbc;
    private final SecretAccessService access;
    SecretClosureRepository(JdbcTemplate jdbc,SecretAccessService access) {this.jdbc=jdbc;this.access=access;}
    public JdbcTemplate jdbc() {return jdbc;}
    Map<String,Object> caseRow(long id,boolean lock) {
        if(lock)jdbc.queryForObject("SELECT case_id FROM secret_response_cases WHERE case_id=? FOR UPDATE",Long.class,id);
        return jdbc.queryForList("""
            SELECT c.*,k.component_state,COALESCE(a.observed_at,c.opened_at) AS exposure_observed_at
            FROM secret_response_cases c JOIN secret_credential_sets k USING(credential_set_id)
            LEFT JOIN secret_exposure_assessments a ON a.assessment_id=c.opening_decision_id WHERE c.case_id=?
            """,id).stream().findFirst().orElseThrow(()->new ApiException(ErrorCode.NOT_FOUND));
    }
    List<Map<String,Object>> related(long id) {
        return jdbc.queryForList("""
            SELECT o.occurrence_id,o.connection_id,o.scope_id,o.exposure_status,o.presence_status,o.last_seen_at,o.last_seen_run_id,
              o.last_complete_coverage_at,o.exposure_assessment_version,s.revision,s.response_origin,s.response_origin_version,s.enabled,
              (s.content_type<>'GITHUB_REPOSITORY_FILES' OR o.source_context_ref=s.approved_ref) AS source_context_current,
              cn.status AS connection_status,cn.scope_version AS connection_version,cn.next_due_at,
              k.component_state,p.policy_result,p.reason_code AS policy_reason,p.binding_id,p.policy_id,p.policy_version,p.requires_reassessment,
              co.case_id AS linked_case_id,co.version AS location_version,co.response_status,co.action_cycle,co.last_material_action_at,co.actions_completed_at,
              last_attempt.run_id AS attempt_run_id,last_attempt.scope_outcome,last_attempt.requested_at AS attempt_requested_at,
              last_attempt.finished_at AS attempt_finished_at,
              EXISTS(SELECT 1 FROM secret_findings f WHERE f.occurrence_id=o.occurrence_id AND f.run_id=o.last_seen_run_id) AS has_findings,
              (NOT EXISTS(SELECT 1 FROM secret_confirmed_real_credentials real WHERE real.credential_set_id=o.credential_set_id)
                AND EXISTS(SELECT 1 FROM secret_findings f WHERE f.occurrence_id=o.occurrence_id AND f.run_id=o.last_seen_run_id)
                AND NOT EXISTS(SELECT 1 FROM secret_findings f WHERE f.occurrence_id=o.occurrence_id AND f.run_id=o.last_seen_run_id
                  AND NOT EXISTS(SELECT 1 FROM secret_current_finding_dispositions d WHERE d.finding_id=f.finding_id))) AS all_corrected,
              historical.revalidation_id AS historical_missing_id,historical.finished_at AS historical_missing_at,
              material.action_id AS last_material_action_id,
              v.revalidation_id,v.status AS revalidation_status,v.run_id AS revalidation_run_id,v.finished_at AS revalidation_finished_at,
              (o.presence_status='MISSING' AND cn.status='ACTIVE' AND s.enabled AND c.case_origin=s.response_origin
                AND co.response_status='REVALIDATION_PENDING' AND v.status='MISSING'
                AND v.connection_id=o.connection_id AND v.scope_id=o.scope_id
                AND (s.content_type<>'GITHUB_REPOSITORY_FILES' OR(o.source_context_ref=s.approved_ref
                  AND EXISTS(SELECT 1 FROM secret_run_scopes context WHERE context.run_id=v.run_id
                    AND context.scope_id=o.scope_id AND context.snapshot_approved_ref=o.source_context_ref)))
                AND v.scope_revision=s.revision AND v.scope_origin_version=s.response_origin_version
                AND v.action_cycle=co.action_cycle AND v.occurrence_version=co.version
                AND v.action_id=material.action_id AND v.last_material_action_at=co.last_material_action_at
                AND v.actions_completed_at=co.actions_completed_at
                AND v.baseline_identity=k.fingerprint AND v.baseline_fingerprint_version=k.fingerprint_key_version
                AND v.runtime_fingerprint_version=v.baseline_fingerprint_version
                AND vr.scope_version=cn.scope_version AND vr.collection_status='SUCCEEDED' AND vr.detection_status='SUCCEEDED'
                AND outcome.job_status='SUCCEEDED' AND outcome.scope_outcome='SUCCEEDED'
                AND outcome.scope_revision=s.revision AND outcome.started_at>=v.requested_at
                AND outcome.finished_at>=co.actions_completed_at AND v.finished_at>=outcome.finished_at
                AND v.requested_at>co.last_material_action_at AND v.requested_at>=co.actions_completed_at
                AND tool.status='SUCCEEDED' AND tool.config_hash=v.baseline_config_hash AND tool.engine_version=v.baseline_engine_version
                AND o.last_seen_at<=v.finished_at AND last_attempt.run_id=v.run_id) AS comparable_post_action_missing
            FROM secret_response_cases c JOIN secret_occurrences o ON o.credential_set_id=c.credential_set_id
            JOIN secret_credential_sets k ON k.credential_set_id=o.credential_set_id
            JOIN secret_connection_scopes s ON s.scope_id=o.scope_id JOIN secret_connections cn ON cn.connection_id=o.connection_id
            JOIN secret_occurrence_policy_results p ON p.occurrence_id=o.occurrence_id
            LEFT JOIN secret_case_occurrences co ON co.case_id=c.case_id AND co.occurrence_id=o.occurrence_id
            LEFT JOIN LATERAL(SELECT so.* FROM secret_scope_outcomes so WHERE so.scope_id=o.scope_id AND so.scope_revision=s.revision
              ORDER BY so.requested_at DESC,so.run_id DESC LIMIT 1)last_attempt ON true
            LEFT JOIN LATERAL(SELECT action_id FROM secret_action_records a WHERE a.case_id=co.case_id AND a.occurrence_id=o.occurrence_id
              AND a.action_cycle=co.action_cycle AND a.action_type IN ('ROTATED','REVOKED','REMOVED_FROM_SOURCE')
              ORDER BY a.performed_at DESC,a.action_id DESC LIMIT 1)material ON true
            LEFT JOIN LATERAL(SELECT * FROM secret_case_revalidations rv WHERE rv.case_id=c.case_id AND rv.occurrence_id=o.occurrence_id
              ORDER BY rv.requested_at DESC,rv.revalidation_id DESC LIMIT 1)v ON true
            LEFT JOIN secret_scan_runs vr ON vr.run_id=v.run_id
            LEFT JOIN secret_scope_outcomes outcome ON outcome.run_id=v.run_id AND outcome.scope_id=o.scope_id
            LEFT JOIN secret_tool_runs tool ON tool.run_scope_id=outcome.run_scope_id AND tool.engine='GITLEAKS'
            LEFT JOIN LATERAL(SELECT h.revalidation_id,h.run_id,h.finished_at FROM secret_case_revalidations h
              JOIN secret_response_cases old_case ON old_case.case_id=h.case_id AND old_case.case_origin=c.case_origin
              JOIN secret_scan_runs hr ON hr.run_id=h.run_id
              JOIN secret_scope_outcomes hs ON hs.run_id=h.run_id AND hs.scope_id=o.scope_id
              JOIN secret_tool_runs ht ON ht.run_scope_id=hs.run_scope_id AND ht.engine='GITLEAKS'
              WHERE h.occurrence_id=o.occurrence_id AND h.status='MISSING' AND h.scope_revision=s.revision
               AND (s.content_type<>'GITHUB_REPOSITORY_FILES' OR(o.source_context_ref=s.approved_ref
                 AND EXISTS(SELECT 1 FROM secret_run_scopes context WHERE context.run_id=h.run_id
                   AND context.scope_id=o.scope_id AND context.snapshot_approved_ref=o.source_context_ref)))
               AND h.scope_origin_version=s.response_origin_version AND o.presence_status='MISSING'
               AND h.baseline_identity=k.fingerprint AND h.baseline_fingerprint_version=k.fingerprint_key_version
               AND h.runtime_fingerprint_version=h.baseline_fingerprint_version AND hr.scope_version=cn.scope_version
               AND hs.scope_outcome='SUCCEEDED' AND hs.job_status='SUCCEEDED' AND ht.status='SUCCEEDED'
               AND ht.config_hash=h.baseline_config_hash AND ht.engine_version=h.baseline_engine_version
               AND h.requested_at>h.last_material_action_at AND h.requested_at>=h.actions_completed_at
               AND hs.started_at>=h.requested_at AND hs.finished_at>=h.actions_completed_at AND h.finished_at>=hs.finished_at
               AND o.last_seen_at<=h.finished_at AND cn.status='ACTIVE' AND s.enabled
               AND last_attempt.run_id=h.run_id
              ORDER BY h.finished_at DESC,h.revalidation_id DESC LIMIT 1)historical ON true
            WHERE c.case_id=? AND (s.response_origin=c.case_origin OR co.case_id IS NOT NULL)
            ORDER BY o.occurrence_id
            """,id);
    }
    boolean fullSecurity(SecretPrincipal actor,List<Map<String,Object>> rows) {
        return !rows.isEmpty()&&rows.stream().allMatch(row->access.hasConnectionRole(actor,number(row,"connection_id"),SecretRole.SECURITY));
    }
    List<Map<String,Object>> visible(SecretPrincipal actor,List<Map<String,Object>> rows) {
        return rows.stream().filter(row->access.canReadOccurrence(actor,number(row,"occurrence_id"))).toList();
    }
    boolean readable(SecretPrincipal actor,long occurrence) {return access.canReadOccurrence(actor,occurrence);}
    void lockUniverse(long id) {
        // Policy changes and new exposure links take this lock before case/occurrence writes too.
        jdbc.queryForObject("SELECT pg_advisory_xact_lock(6197611306)",Object.class);
        var c=caseRow(id,true);
        // FK-backed new locations and validation observations serialize behind the closure decision.
        jdbc.queryForObject("SELECT credential_set_id FROM secret_credential_sets WHERE credential_set_id=? FOR UPDATE",Long.class,c.get("credential_set_id"));
        jdbc.queryForList("""
            SELECT o.occurrence_id FROM secret_occurrences o JOIN secret_connection_scopes s ON s.scope_id=o.scope_id
            WHERE o.credential_set_id=? AND (s.response_origin=? OR EXISTS(
                SELECT 1 FROM secret_case_occurrences co WHERE co.case_id=? AND co.occurrence_id=o.occurrence_id))
            ORDER BY o.occurrence_id FOR UPDATE OF o
            """,c.get("credential_set_id"),c.get("case_origin"),id);
        jdbc.queryForList("SELECT occurrence_id FROM secret_case_occurrences WHERE case_id=? ORDER BY occurrence_id FOR UPDATE",id);
    }
    List<Map<String,Object>> lifecycle(Map<String,Object> c) {
        return jdbc.queryForList("""
            SELECT e.* FROM secret_current_lifecycle_evidence e
            WHERE e.credential_set_id=? AND (e.case_id=? OR EXISTS(SELECT 1 FROM secret_lifecycle_evidence_applications application
              WHERE application.case_id=? AND application.evidence_id=e.evidence_id AND application.credential_set_id=e.credential_set_id))
             AND e.performed_at>=? ORDER BY e.evidence_id
            """,c.get("credential_set_id"),c.get("case_id"),c.get("case_id"),c.get("exposure_observed_at"));
    }
    OffsetDateTime now() {return jdbc.queryForObject("SELECT clock_timestamp()",OffsetDateTime.class);}
    static Long nullable(Map<String,Object> row,String field) {return row.get(field)==null?null:((Number)row.get(field)).longValue();}
    static String text(Map<String,Object> row,String field) {return row.get(field)==null?null:row.get(field).toString();}
    static boolean yes(Map<String,Object> row,String field) {return Boolean.TRUE.equals(row.get(field));}
}
