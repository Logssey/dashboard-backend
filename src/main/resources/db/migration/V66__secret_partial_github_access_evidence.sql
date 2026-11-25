-- Repository metadata can be observed even when unrelated content is excluded.
-- Keep PARTIAL collection coverage and allow only finding-bound GitHub access observations.
-- All other evidence kinds retain the original SUCCEEDED-parent requirement.
DO $migration$
DECLARE definition TEXT;
        original TEXT := $original$WHEN 'RUN_SCOPE' THEN SELECT NEW.source_kind='PROVIDER_OBSERVATION' AND EXISTS(SELECT 1 FROM secret_run_scopes WHERE run_scope_id=parent_id AND scope_id=NEW.scope_id AND scope_revision=parent_version AND collection_status='SUCCEEDED') INTO permitted;$original$;
        replacement TEXT := $replacement$WHEN 'RUN_SCOPE' THEN
   SELECT NEW.source_kind='PROVIDER_OBSERVATION' AND EXISTS(
    SELECT 1 FROM secret_run_scopes rs
    WHERE rs.run_scope_id=parent_id AND rs.scope_id=NEW.scope_id AND rs.scope_revision=parent_version
     AND (rs.collection_status='SUCCEEDED' OR (
      rs.collection_status='PARTIAL'
      AND NEW.record_kind='ASSERTION' AND NEW.kind='ACCESS_SCOPE'
      AND NEW.writer_service_id='GITHUB_REPOSITORY_METADATA_V1'
      AND NEW.verification_level='PROVIDER_OBSERVED'
      AND NEW.applicability_basis='OBSERVATION_ONLY'
      AND NEW.identity_binding_status='NOT_APPLICABLE'
      AND ref->>'role'='ASSERTS'
      AND EXISTS(
       SELECT 1 FROM secret_scan_runs r JOIN secret_connections c USING(connection_id)
       WHERE r.run_id=rs.run_id AND c.provider='GITHUB'
        AND r.connection_id=NEW.collector_connection_id AND r.connection_id=o.connection_id)
      AND EXISTS(
       SELECT 1 FROM secret_findings f JOIN secret_tool_runs t USING(tool_run_id)
       WHERE t.run_scope_id=rs.run_scope_id AND f.occurrence_id=NEW.occurrence_id)
     ))) INTO permitted;$replacement$;
BEGIN
 SELECT pg_get_functiondef('secret_risk_reference_guard()'::regprocedure) INTO definition;
 IF position(original IN definition)=0 THEN
  RAISE EXCEPTION 'RISK_REFERENCE_GUARD_BASELINE_MISMATCH';
 END IF;
 EXECUTE replace(definition,original,replacement);
END
$migration$;
