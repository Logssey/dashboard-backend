package com.logssey.secretworker;
import java.time.OffsetDateTime;
import org.springframework.jdbc.core.JdbcTemplate;
/** Absence is an explicit complete, comparable observation; failure never erases exposure/lifecycle facts. */
final class SecretFullScanPresence {
 private final JdbcTemplate jdbc;
 SecretFullScanPresence(JdbcTemplate jdbc){this.jdbc=jdbc;}
 void reconcile(long runId,OffsetDateTime observedAt){
  jdbc.update("""
   WITH observation AS (
    SELECT o.occurrence_id,
      COALESCE(j.status='SUCCEEDED' AND r.result_status='SUCCEEDED' AND r.collection_status='SUCCEEDED'
       AND r.detection_status IN ('SUCCEEDED','SKIPPED') AND cn.status='ACTIVE' AND sc.enabled
       AND rs.collection_status='SUCCEEDED' AND rs.object_count IS NOT NULL AND rs.finished_at IS NOT NULL
       AND rs.detection_stage_status='SUCCEEDED' AND current_tool.status='SUCCEEDED'
       AND rs.evidence_version IS NOT NULL AND baseline.scope_id=rs.scope_id AND rs.scope_revision=sc.revision AND rs.scope_revision=baseline.scope_revision
       AND rs.snapshot_content_type=baseline.snapshot_content_type AND rs.snapshot_content_type=sc.content_type
       AND right(rs.snapshot_content_type,9)<>'_METADATA' AND rs.snapshot_origin=baseline.snapshot_origin AND rs.snapshot_origin=sc.response_origin
       AND r.scope_version=cn.scope_version AND baseline.connection_version=r.scope_version
       AND current_tool.scope_origin_version=sc.response_origin_version AND current_tool.scope_origin_version=baseline.scope_origin_version
       AND baseline.detector_status='SUCCEEDED' AND baseline.collection_status='SUCCEEDED'
       AND current_tool.engine_version=baseline.engine_version AND current_tool.config_hash=baseline.config_hash
       AND current_tool.fingerprint_key_version=baseline.fingerprint_key_version
       AND k.fingerprint_key_version=current_tool.fingerprint_key_version
       AND r.requested_at>baseline.detected_at AND rs.started_at>=r.requested_at AND rs.finished_at>=rs.started_at,false) AS comparable
    FROM secret_scan_runs r JOIN secret_jobs j ON j.job_id=r.job_id AND j.kind='FULL_SCAN'
    JOIN secret_connections cn ON cn.connection_id=r.connection_id
    JOIN secret_run_scopes rs ON rs.run_id=r.run_id JOIN secret_connection_scopes sc ON sc.scope_id=rs.scope_id
    JOIN secret_occurrences o ON o.scope_id=rs.scope_id AND o.connection_id=r.connection_id
    JOIN secret_credential_sets k ON k.credential_set_id=o.credential_set_id AND k.component_state IN ('CONFIRMED','CANDIDATE')
    LEFT JOIN secret_tool_runs current_tool ON current_tool.run_scope_id=rs.run_scope_id AND current_tool.engine='GITLEAKS'
    LEFT JOIN LATERAL (
      SELECT old_scope.scope_id,old_scope.scope_revision,old_scope.snapshot_content_type,old_scope.snapshot_origin,old_run.scope_version AS connection_version,
        old_tool.status AS detector_status,old_scope.collection_status,old_tool.engine_version,old_tool.config_hash,old_tool.fingerprint_key_version,old_tool.scope_origin_version,f.detected_at
      FROM secret_findings f JOIN secret_tool_runs old_tool ON old_tool.tool_run_id=f.tool_run_id
      JOIN secret_run_scopes old_scope ON old_scope.run_scope_id=old_tool.run_scope_id
      JOIN secret_scan_runs old_run ON old_run.run_id=f.run_id
      WHERE f.occurrence_id=o.occurrence_id AND f.run_id<>r.run_id
      ORDER BY f.detected_at DESC,f.finding_id DESC LIMIT 1
    )baseline ON true
    WHERE r.run_id=? AND NOT EXISTS(SELECT 1 FROM secret_findings f WHERE f.occurrence_id=o.occurrence_id AND f.run_id=r.run_id)
   )
   UPDATE secret_occurrences o SET presence_status=CASE WHEN observation.comparable THEN 'MISSING' ELSE 'UNKNOWN' END,
    last_complete_coverage_at=CASE WHEN observation.comparable THEN ? ELSE o.last_complete_coverage_at END
   FROM observation WHERE observation.occurrence_id=o.occurrence_id
   """,runId,observedAt);
 }
}
