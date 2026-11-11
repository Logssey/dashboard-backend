-- The upgraded worker opts in when it performs validation. Older workers and historical
-- runs retain NULL, including during a rolling deployment.
ALTER TABLE secret_scan_runs ADD COLUMN validation_reuse_version SMALLINT,
 ADD COLUMN validation_reuse_attempt INTEGER;

CREATE TABLE secret_validation_reuses (
 reuse_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 run_id BIGINT NOT NULL REFERENCES secret_scan_runs ON DELETE CASCADE,
 run_scope_id BIGINT NOT NULL REFERENCES secret_run_scopes ON DELETE CASCADE,
 attempt_no INTEGER NOT NULL CHECK(attempt_no>0),
 credential_set_id BIGINT NOT NULL REFERENCES secret_credential_sets,
 source_attempt_id BIGINT NOT NULL REFERENCES secret_validation_attempts,
 reused_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(run_id,attempt_no,run_scope_id,credential_set_id)
);

ALTER TABLE secret_run_execution_events DROP CONSTRAINT secret_run_execution_events_operation_code_check;
ALTER TABLE secret_run_execution_events ADD CONSTRAINT secret_run_execution_events_operation_code_check
 CHECK(operation_code IN(
  'RUN_REGISTERED','WORKER_CLAIM','RUN_RETRY','RUN_FINISHED','STAGE_SUMMARY','SCOPE_COLLECTION',
  'GITHUB_REF_GET','GITHUB_COMMIT_GET','GITHUB_TREE_GET','GITHUB_BLOB_GET','GITHUB_REPOSITORY_GET','GITHUB_TOKEN_EXCHANGE',
  'NOTION_PAGE_GET','NOTION_BLOCK_CHILDREN_LIST','AWS_GET_CALLER_IDENTITY','AWS_LIST_USERS','AWS_LIST_ACCESS_KEYS',
  'AWS_GET_ACCESS_KEY_LAST_USED','AWS_GET_ACCOUNT_SUMMARY','AWS_LIST_SECRETS','AWS_DESCRIBE_PARAMETERS','AWS_LIST_BUCKETS',
  'AWS_GET_SECRET_VALUE','AWS_GET_PARAMETER','AWS_HEAD_OBJECT','AWS_GET_OBJECT','GITLEAKS_SCAN','CANDIDATE_NORMALIZATION',
  'FINDINGS_COMMIT','AWS_CREDENTIAL_CHECK','GITHUB_CREDENTIAL_CHECK','NOTION_CREDENTIAL_CHECK','CREDENTIAL_CHECK',
  'CREDENTIAL_RESULT_REUSED'));

-- The worker records a reuse while its lease and the exact approval context are current.
-- Authentication timestamps and responses continue to belong to the original provider attempt.
CREATE FUNCTION secret_record_validation_reuse(
 target_job BIGINT,target_token UUID,target_generation BIGINT,target_scope BIGINT,
 target_source BIGINT,target_context TEXT,target_dedup BYTEA)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE j secret_jobs%ROWTYPE; s secret_run_scopes%ROWTYPE; a secret_validation_attempts%ROWTYPE;
        run BIGINT; inserted BIGINT;
BEGIN
 SELECT * INTO j FROM secret_jobs WHERE job_id=target_job FOR UPDATE;
 IF NOT FOUND OR j.status<>'LEASED' OR j.lease_token IS DISTINCT FROM target_token
  OR j.lease_generation<>target_generation OR j.lease_until<=clock_timestamp()
  OR j.purpose='CREDENTIAL_VALIDITY' THEN RETURN false; END IF;
 IF j.requested_by_user_id IS NOT NULL AND NOT EXISTS(
  SELECT 1 FROM secret_role_grants g WHERE g.user_id=j.requested_by_user_id AND g.revoked_at IS NULL
   AND (g.connection_id IS NULL OR g.connection_id=j.connection_id)
   AND (g.role='SECURITY' OR (g.role='OPERATIONS' AND j.kind='FULL_SCAN')
    OR (g.role='REMEDIATOR' AND EXISTS(SELECT 1 FROM secret_case_occurrences co
     JOIN secret_response_cases c USING(case_id) WHERE co.occurrence_id=j.target_occurrence_id AND c.is_current
      AND (co.assigned_user_id=j.requested_by_user_id OR (co.assigned_user_id IS NULL AND EXISTS(
       SELECT 1 FROM secret_team_memberships tm WHERE tm.user_id=j.requested_by_user_id
        AND tm.removed_at IS NULL AND tm.team_name=co.assigned_team))))))) THEN RETURN false; END IF;
 SELECT run_id INTO run FROM secret_scan_runs WHERE job_id=target_job;
 SELECT * INTO s FROM secret_run_scopes WHERE run_scope_id=target_scope AND run_id=run;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT source.* INTO a FROM secret_current_validation_attempts source
  JOIN secret_validation_context context ON context.occurrence_id=source.occurrence_id
  WHERE source.attempt_id=target_source AND source.scope_id=s.scope_id
   AND source.result IN('VALID','INVALID') AND source.dedup_key=target_dedup
   AND context.context_version=target_context AND s.scope_revision=context.scope_revision
   AND context.connection_id=j.connection_id
   AND (context.action_performed_at IS NULL OR source.provider_checked_at>context.action_performed_at)
   AND EXISTS(SELECT 1 FROM secret_findings f JOIN secret_tool_runs tool USING(tool_run_id)
    WHERE f.run_id=run AND tool.run_scope_id=target_scope AND f.occurrence_id=source.occurrence_id)
   AND source.cycle_key=CASE WHEN j.purpose='CREDENTIAL_VALIDITY' THEN 'manual:'||j.job_id
    ELSE 'scheduled:'||floor(extract(epoch FROM j.scheduled_at)/21600)::bigint END;
 IF NOT FOUND THEN RETURN false; END IF;
 -- Repeated encounters in the original scope/attempt are already counted as a new request.
 IF a.run_id=run AND a.attempt_no=j.attempt_no THEN RETURN true; END IF;
 INSERT INTO secret_validation_reuses(run_id,run_scope_id,attempt_no,credential_set_id,source_attempt_id)
 VALUES(run,target_scope,j.attempt_no,a.credential_set_id,a.attempt_id)
 ON CONFLICT(run_id,attempt_no,run_scope_id,credential_set_id) DO NOTHING
 RETURNING reuse_id INTO inserted;
 IF inserted IS NOT NULL THEN
  PERFORM secret_append_execution_event(run,target_scope,j.attempt_no,j.lease_generation,'VALIDATION',
   'CREDENTIAL_RESULT_REUSED','STARTED',NULL,NULL,NULL,NULL,NULL,'reuse:'||inserted||':start',false);
  PERFORM secret_append_execution_event(run,target_scope,j.attempt_no,j.lease_generation,'VALIDATION',
   'CREDENTIAL_RESULT_REUSED','COMPLETED',NULL,NULL,1,NULL,NULL,'reuse:'||inserted||':complete',false);
 END IF;
 RETURN true;
END $$;
REVOKE EXECUTE ON FUNCTION secret_record_validation_reuse(bigint,uuid,bigint,bigint,bigint,text,bytea) FROM PUBLIC;

CREATE OR REPLACE FUNCTION secret_record_scope_evidence(target BIGINT, validation_failed BOOLEAN)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    s secret_run_scopes%ROWTYPE;
    t secret_tool_runs%ROWTYPE;
    a RECORD;
    candidates BIGINT;
    current_attempt INTEGER;
BEGIN
    SELECT * INTO STRICT s FROM secret_run_scopes WHERE run_scope_id=target;
    IF s.evidence_version IS NULL THEN RETURN; END IF;
    IF right(s.snapshot_content_type,9)='_METADATA' THEN
        UPDATE secret_run_scopes SET detection_stage_status='SKIPPED', detection_reason_code='NOT_APPLICABLE_METADATA',
            validation_stage_status='SKIPPED', validation_reason_code='NOT_APPLICABLE_METADATA', validation_required=false
        WHERE run_scope_id=target;
        RETURN;
    END IF;
    SELECT j.attempt_no INTO current_attempt FROM secret_scan_runs r JOIN secret_jobs j USING(job_id) WHERE r.run_id=s.run_id;
    SELECT * INTO t FROM secret_tool_runs WHERE run_scope_id=target AND engine='GITLEAKS';
    SELECT count(*) INTO candidates FROM secret_findings WHERE tool_run_id=t.tool_run_id;
    WITH observations AS (
      SELECT v.credential_set_id,v.result,v.reason_code
      FROM secret_validation_attempts v
      WHERE v.run_id=s.run_id AND v.attempt_state='COMPLETED'
        AND (v.evidence_version=0 OR v.attempt_no=current_attempt AND v.scope_id=s.scope_id)
      UNION ALL
      SELECT v.credential_set_id,v.result,v.reason_code FROM secret_validation_reuses reuse
      JOIN secret_validation_attempts v ON v.attempt_id=reuse.source_attempt_id
      WHERE reuse.run_id=s.run_id AND reuse.run_scope_id=target AND reuse.attempt_no=current_attempt
    )
    SELECT count(*) AS total,
        count(*) FILTER(WHERE v.result IN ('VALID','INVALID')) AS checked,
        count(*) FILTER(WHERE v.result='UNKNOWN' OR v.result='UNCHECKED' AND v.reason_code NOT IN ('DISABLED','SYNTHETIC_FIXTURE','SOURCE_GUARD_BLOCKED','VALIDATOR_NOT_ALLOWED')) AS incomplete,
        count(*) FILTER(WHERE v.reason_code='DISABLED') AS disabled,
        count(*) FILTER(WHERE v.reason_code='SYNTHETIC_FIXTURE') AS fixture,
        count(*) FILTER(WHERE v.reason_code='SOURCE_GUARD_BLOCKED') AS guarded,
        count(*) FILTER(WHERE v.reason_code='VALIDATOR_NOT_ALLOWED') AS disallowed
    INTO a FROM observations v
    WHERE EXISTS (
        SELECT 1 FROM secret_findings f JOIN secret_occurrences o ON o.occurrence_id=f.occurrence_id
        WHERE f.tool_run_id=t.tool_run_id AND o.credential_set_id=v.credential_set_id);
    UPDATE secret_run_scopes SET
        detection_stage_status=COALESCE(t.status, CASE WHEN collection_status='SUCCEEDED' AND object_count=0 THEN 'SKIPPED' END),
        detection_reason_code=CASE WHEN t.tool_run_id IS NOT NULL THEN t.failure_code
             WHEN collection_status='SUCCEEDED' AND object_count=0 THEN 'NO_OBJECTS' ELSE 'DETECTION_NOT_RUN' END,
        validation_stage_status=CASE WHEN validation_failed OR a.incomplete>0 THEN 'PARTIAL'
             WHEN a.checked>0 THEN 'SUCCEEDED' ELSE 'SKIPPED' END,
        validation_reason_code=CASE WHEN validation_failed THEN 'VALIDATION_ATTEMPT_FAILED'
             WHEN a.incomplete>0 THEN 'VALIDATION_INCONCLUSIVE' WHEN a.checked>0 THEN NULL
             WHEN a.disabled>0 THEN 'VALIDATION_DISABLED' WHEN a.fixture>0 THEN 'SYNTHETIC_FIXTURE'
             WHEN a.guarded>0 THEN 'SOURCE_GUARD_BLOCKED'
             WHEN a.disallowed>0 THEN 'VALIDATOR_NOT_ALLOWED'
             WHEN candidates=0 THEN 'NO_CANDIDATES' ELSE 'NO_SUPPORTED_VALIDATOR' END,
        validation_required=(validation_failed OR a.checked>0 OR a.incomplete>0)
    WHERE run_scope_id=target;
END $$;
