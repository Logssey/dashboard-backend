-- Capture source approval coordinates separately from the mutable current scope.
ALTER TABLE secret_run_scopes ADD COLUMN snapshot_approved_ref VARCHAR(500);
ALTER TABLE secret_occurrences
 ADD COLUMN source_context_ref VARCHAR(500),
 ADD COLUMN source_context_key BYTEA NOT NULL DEFAULT ''::bytea,
 ADD COLUMN source_context_status VARCHAR(24) NOT NULL DEFAULT 'UNKNOWN'
   CHECK(source_context_status IN ('OBSERVED','RECONSTRUCTED','UNKNOWN','NOT_APPLICABLE'));

CREATE OR REPLACE FUNCTION secret_capture_run_scope() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 SELECT s.revision,s.content_type,s.response_origin,s.safe_display_alias,s.approved_ref
 INTO NEW.scope_revision,NEW.snapshot_content_type,NEW.snapshot_origin,NEW.safe_display_alias,NEW.snapshot_approved_ref
 FROM secret_connection_scopes s WHERE s.scope_id=NEW.scope_id;
 NEW.evidence_version:=1;
 RETURN NEW;
END $$;

-- Revision-consistent snapshots can be reconstructed. Conflicting history stays unknown.
UPDATE secret_run_scopes rs SET snapshot_approved_ref=s.approved_ref
FROM secret_connection_scopes s
WHERE s.scope_id=rs.scope_id AND rs.scope_revision=s.revision
 AND rs.snapshot_content_type=s.content_type AND rs.snapshot_origin=s.response_origin;

WITH consistent AS (
 SELECT o.occurrence_id,min(rs.snapshot_approved_ref) AS reference
 FROM secret_occurrences o JOIN secret_connection_scopes s ON s.scope_id=o.scope_id
 JOIN secret_findings f ON f.occurrence_id=o.occurrence_id
 JOIN secret_tool_runs t ON t.tool_run_id=f.tool_run_id
 JOIN secret_run_scopes rs ON rs.run_scope_id=t.run_scope_id
 WHERE s.content_type='GITHUB_REPOSITORY_FILES' AND secret_github_scope_parts(s.approved_ref) IS NOT NULL
 GROUP BY o.occurrence_id
 HAVING bool_and(rs.scope_id=o.scope_id AND rs.snapshot_approved_ref IS NOT NULL)
    AND count(DISTINCT rs.snapshot_approved_ref)=1
)
UPDATE secret_occurrences o SET source_context_ref=c.reference,
 source_context_key=sha256(convert_to(c.reference,'UTF8')),source_context_status='RECONSTRUCTED'
FROM consistent c WHERE c.occurrence_id=o.occurrence_id;

UPDATE secret_occurrences o SET source_context_status='NOT_APPLICABLE'
FROM secret_connection_scopes s WHERE s.scope_id=o.scope_id AND s.content_type<>'GITHUB_REPOSITORY_FILES';
UPDATE secret_occurrences o SET presence_status='UNKNOWN'
FROM secret_connection_scopes s WHERE s.scope_id=o.scope_id AND s.content_type='GITHUB_REPOSITORY_FILES'
 AND o.source_context_ref IS NULL;

ALTER TABLE secret_occurrences DROP CONSTRAINT uq_secret_occurrence_location;
ALTER TABLE secret_occurrences ADD CONSTRAINT uq_secret_occurrence_location
 UNIQUE(credential_set_id,connection_id,scope_id,source_context_key,source_object_ref,location_key);

CREATE FUNCTION secret_capture_occurrence_context() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE kind TEXT; reference TEXT; captured TEXT;
BEGIN
 SELECT s.content_type,s.approved_ref INTO kind,reference FROM secret_connection_scopes s
 WHERE s.scope_id=NEW.scope_id AND s.connection_id=NEW.connection_id;
 IF TG_OP='INSERT' AND NEW.source_context_ref IS NULL AND kind='GITHUB_REPOSITORY_FILES' THEN
   SELECT rs.snapshot_approved_ref INTO captured FROM secret_run_scopes rs
   WHERE rs.run_id=NEW.last_seen_run_id AND rs.scope_id=NEW.scope_id;
   NEW.source_context_ref:=COALESCE(captured,reference);
   NEW.source_context_status:=CASE WHEN captured IS NULL THEN 'RECONSTRUCTED' ELSE 'OBSERVED' END;
 END IF;
 IF kind='GITHUB_REPOSITORY_FILES' THEN
   IF secret_github_scope_parts(NEW.source_context_ref) IS NULL THEN
     NEW.source_context_ref:=NULL;NEW.source_context_status:='UNKNOWN';
   END IF;
 ELSE
   NEW.source_context_ref:=NULL;NEW.source_context_status:='NOT_APPLICABLE';
 END IF;
 NEW.source_context_key:=CASE WHEN NEW.source_context_ref IS NULL THEN ''::bytea
   ELSE sha256(convert_to(NEW.source_context_ref,'UTF8')) END;
 RETURN NEW;
END $$;
CREATE TRIGGER secret_capture_occurrence_context
 BEFORE INSERT OR UPDATE OF source_context_ref ON secret_occurrences
 FOR EACH ROW EXECUTE FUNCTION secret_capture_occurrence_context();

CREATE OR REPLACE VIEW secret_current_raw_findings AS
SELECT f.finding_id,f.occurrence_id,f.run_id,f.rule_id,f.rule_version,f.detected_at
FROM secret_findings f JOIN secret_occurrences o ON o.occurrence_id=f.occurrence_id
JOIN secret_connection_scopes s ON s.scope_id=o.scope_id
LEFT JOIN secret_tool_runs t ON t.tool_run_id=f.tool_run_id
WHERE o.presence_status='PRESENT' AND s.enabled AND o.last_seen_run_id=f.run_id
 AND (s.content_type<>'GITHUB_REPOSITORY_FILES' OR o.source_context_ref=s.approved_ref)
 AND f.run_id=(SELECT so.run_id FROM secret_scope_outcomes so
   WHERE so.scope_id=o.scope_id AND so.scope_revision=s.revision
    AND so.collection_status IN ('SUCCEEDED','PARTIAL') AND so.job_status='SUCCEEDED'
    AND (so.scope_outcome='SUCCEEDED' OR (o.latest_object_version IS NOT NULL
      AND t.run_scope_id=so.run_scope_id AND t.status IN ('SUCCEEDED','PARTIAL')))
    AND so.finished_at IS NOT NULL
   ORDER BY so.finished_at DESC,so.run_id DESC LIMIT 1);
