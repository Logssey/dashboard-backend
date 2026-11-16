-- File-level positive evidence remains usable when another object is unreadable.
-- Complete coverage and retirement checks retain their independent scope requirements.
ALTER TABLE secret_worker_heartbeats ADD COLUMN active_job_ids BIGINT[] NOT NULL DEFAULT '{}',
 ADD COLUMN validation_issuers TEXT[];

ALTER TABLE secret_connections ADD COLUMN settings_version BIGINT NOT NULL DEFAULT 1 CHECK(settings_version>0);
ALTER TABLE secret_scan_runs ADD COLUMN retry_of_run_id BIGINT REFERENCES secret_scan_runs;

ALTER TABLE secret_run_scopes
 ADD COLUMN exclusion_reasons JSONB,
 ADD CONSTRAINT ck_secret_scope_exclusion_reasons CHECK(exclusion_reasons IS NULL OR jsonb_typeof(exclusion_reasons)='object');

CREATE OR REPLACE VIEW secret_current_raw_findings AS
SELECT f.finding_id,f.occurrence_id,f.run_id,f.rule_id,f.rule_version,f.detected_at
FROM secret_findings f JOIN secret_occurrences o ON o.occurrence_id=f.occurrence_id
JOIN secret_connection_scopes s ON s.scope_id=o.scope_id
LEFT JOIN secret_tool_runs t ON t.tool_run_id=f.tool_run_id
WHERE o.presence_status='PRESENT' AND s.enabled AND o.last_seen_run_id=f.run_id
 AND f.run_id=(SELECT so.run_id FROM secret_scope_outcomes so
   WHERE so.scope_id=o.scope_id AND so.scope_revision=s.revision
    AND so.collection_status IN ('SUCCEEDED','PARTIAL') AND so.job_status='SUCCEEDED'
    AND (so.scope_outcome='SUCCEEDED' OR (o.latest_object_version IS NOT NULL
      AND t.run_scope_id=so.run_scope_id AND t.status IN ('SUCCEEDED','PARTIAL')))
    AND so.finished_at IS NOT NULL
   ORDER BY so.finished_at DESC,so.run_id DESC LIMIT 1);
