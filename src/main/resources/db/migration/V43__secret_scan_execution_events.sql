-- Operational facts only. Legacy runs intentionally have no synthetic execution history.
ALTER TABLE secret_scan_runs
 ADD COLUMN execution_trace_version SMALLINT,
 ADD COLUMN execution_recorded_at TIMESTAMPTZ,
 ADD COLUMN execution_event_count INTEGER NOT NULL DEFAULT 0 CHECK(execution_event_count BETWEEN 0 AND 2000),
 ADD COLUMN execution_suppressed_count BIGINT NOT NULL DEFAULT 0 CHECK(execution_suppressed_count>=0),
 ADD COLUMN execution_last_activity_at TIMESTAMPTZ,
 ADD COLUMN execution_events_expired_at TIMESTAMPTZ;
ALTER TABLE secret_scan_runs ALTER COLUMN execution_trace_version SET DEFAULT 1;
ALTER TABLE secret_scan_runs ALTER COLUMN execution_recorded_at SET DEFAULT clock_timestamp();

CREATE TABLE secret_run_execution_events (
 run_id BIGINT NOT NULL REFERENCES secret_scan_runs ON DELETE CASCADE,
 event_id INTEGER NOT NULL CHECK(event_id BETWEEN 1 AND 2000),
 event_key VARCHAR(120) NOT NULL,
 run_scope_id BIGINT REFERENCES secret_run_scopes ON DELETE CASCADE,
 attempt_no INTEGER NOT NULL CHECK(attempt_no>=0),
 lease_generation BIGINT NOT NULL CHECK(lease_generation>=0),
 stage VARCHAR(12) NOT NULL CHECK(stage IN('QUEUE','COLLECTION','DETECTION','VALIDATION','RESULT')),
 operation_code VARCHAR(40) NOT NULL CHECK(operation_code IN(
  'RUN_REGISTERED','WORKER_CLAIM','RUN_RETRY','RUN_FINISHED','STAGE_SUMMARY','SCOPE_COLLECTION',
  'GITHUB_REF_GET','GITHUB_COMMIT_GET','GITHUB_TREE_GET','GITHUB_BLOB_GET','GITHUB_REPOSITORY_GET','GITHUB_TOKEN_EXCHANGE',
  'NOTION_PAGE_GET','NOTION_BLOCK_CHILDREN_LIST','AWS_GET_CALLER_IDENTITY','AWS_LIST_USERS','AWS_LIST_ACCESS_KEYS',
  'AWS_GET_ACCESS_KEY_LAST_USED','AWS_GET_ACCOUNT_SUMMARY','AWS_LIST_SECRETS','AWS_DESCRIBE_PARAMETERS','AWS_LIST_BUCKETS',
  'AWS_GET_SECRET_VALUE','AWS_GET_PARAMETER','AWS_HEAD_OBJECT','AWS_GET_OBJECT','GITLEAKS_SCAN','CANDIDATE_NORMALIZATION',
  'FINDINGS_COMMIT','AWS_CREDENTIAL_CHECK','GITHUB_CREDENTIAL_CHECK','NOTION_CREDENTIAL_CHECK','CREDENTIAL_CHECK')),
 outcome VARCHAR(20) NOT NULL CHECK(outcome IN('STARTED','COMPLETED','PARTIAL','FAILED','SKIPPED','RETRY_SCHEDULED','CANCELLED')),
 http_status INTEGER CHECK(http_status BETWEEN 100 AND 599),
 reason_code VARCHAR(80),
 processed_count BIGINT CHECK(processed_count>=0),
 total_count BIGINT CHECK(total_count>=0),
 duration_ms BIGINT CHECK(duration_ms BETWEEN 0 AND 86400000),
 lifecycle BOOLEAN NOT NULL,
 observed_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(run_id,event_id), UNIQUE(run_id,event_key)
);
CREATE TABLE secret_run_execution_stage_facts (
 run_id BIGINT NOT NULL REFERENCES secret_scan_runs ON DELETE CASCADE,
 attempt_no INTEGER NOT NULL CHECK(attempt_no>=0),
 stage VARCHAR(12) NOT NULL CHECK(stage IN('QUEUE','COLLECTION','DETECTION','VALIDATION','RESULT')),
 started_at TIMESTAMPTZ,finished_at TIMESTAMPTZ,
 completed_objects BIGINT NOT NULL DEFAULT 0 CHECK(completed_objects>=0),
 completed_scopes BIGINT NOT NULL DEFAULT 0 CHECK(completed_scopes>=0),
 PRIMARY KEY(run_id,attempt_no,stage)
);
CREATE INDEX idx_secret_execution_attempt ON secret_run_execution_events(run_id,attempt_no,event_id);

-- These values are registered by the implementation. Arbitrary provider text cannot be stored.
CREATE FUNCTION secret_execution_safe_reason(value TEXT) RETURNS TEXT LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN value IN(
 'OPERATION_FAILED','LEASE_EXPIRED','PROCESSOR_FAILURE','INCOMPLETE_RUN','SOURCE_UNAVAILABLE',
 'SOURCE_ACCESS_DENIED','SOURCE_RATE_LIMITED','DETECTOR_TEMPORARY','VALIDATOR_TEMPORARY',
 'VALIDATION_ATTEMPT_FAILED','VALIDATION_INCONCLUSIVE','NOT_APPLICABLE_METADATA','NO_OBJECTS','NO_CANDIDATES',
 'NO_SUPPORTED_VALIDATOR','VALIDATION_DISABLED','SYNTHETIC_FIXTURE','AUTH_REJECTED','AUTH_ACCEPTED',
 'AUTHENTICATION_FAILED','NETWORK_ERROR','TIMEOUT','RATE_LIMITED','ACCESS_DENIED','MALFORMED_RESPONSE',
 'SOURCE_GUARD_BLOCKED','VALIDATOR_DISABLED','UNSUPPORTED_TYPE','INCOMPLETE_CREDENTIAL','CONFIGURATION_ERROR',
 'RETRY_BUDGET_EXHAUSTED','RATE_BUDGET_EXHAUSTED','APPROVAL_CHANGED','CANCELLED',
 'AUTHENTICATION_REJECTED','INVALID_ACCESS_KEY','SIGNATURE_AMBIGUOUS','EXPIRED_SESSION','INCOMPLETE_PAIR','MISSING_SESSION_TOKEN','ACCESS_AMBIGUOUS','CLIENT_FAILURE','NOT_APPROVED','CREDENTIAL_MISMATCH',
 'DISABLED','UNSUPPORTED','AUTHENTICATED','AUTH_REJECTED','INVALID_CLIENT_TOKEN','INVALID_SIGNATURE','EXPIRED','ACCESS_LIMITED','PROVIDER_UNAVAILABLE','NETWORK_FAILURE','UNEXPECTED_RESPONSE','INCOMPLETE','SOURCE_GUARD_BLOCKED',
 'GITHUB_AUTHENTICATED','GITHUB_BAD_CREDENTIALS','GITHUB_UNAUTHORIZED','GITHUB_FORBIDDEN','GITHUB_RATE_LIMITED',
 'GITHUB_PROVIDER_UNAVAILABLE','GITHUB_NETWORK_ERROR','GITHUB_TIMEOUT','GITHUB_MALFORMED_RESPONSE',
 'NOTION_AUTHENTICATED','NOTION_UNAUTHORIZED','NOTION_RESTRICTED_RESOURCE','NOTION_RATE_LIMITED','NOTION_TIMEOUT',
 'NOTION_SOURCE_UNAVAILABLE','NOTION_MALFORMED_RESPONSE','AWS_AUTHENTICATED','AWS_INVALID_CLIENT_TOKEN_ID',
 'AWS_SIGNATURE_DOES_NOT_MATCH','AWS_EXPIRED_TOKEN','AWS_ACCESS_DENIED','AWS_THROTTLED','AWS_UNAVAILABLE',
 'GITHUB_ACCESS_DENIED','GITHUB_SOURCE_UNAVAILABLE','GITHUB_TREE_LIMIT','GITHUB_FILE_LIMIT','GITHUB_TREE_TRUNCATED',
 'GITHUB_FILE_TOO_LARGE','GITHUB_TOTAL_BYTES_LIMIT','GITHUB_BINARY_FILE','GITHUB_UNSUPPORTED_OBJECT',
 'AWS_CONTENT_READ_DISABLED','AWS_CONTENT_ACCESS_DENIED','AWS_CONTENT_NOT_FOUND','AWS_CONTENT_SOURCE_UNAVAILABLE',
 'AWS_CONTENT_OBJECT_TOO_LARGE','AWS_CONTENT_NON_TEXT','AWS_ROOT_ACCESS_KEYS_PRESENT','AWS_ROOT_KEY_COVERAGE_UNKNOWN',
 'NOTION_NOT_FOUND','NOTION_ACCESS_DENIED','NOTION_CONTENT_CHANGED','NOTION_UNSUPPORTED_BLOCK','NOTION_BLOCK_LIMIT',
 'NOTION_DEPTH_LIMIT','NOTION_TEXT_LIMIT','NOTION_REQUEST_LIMIT','NOTION_CURSOR_LOOP','NOTION_COLLECTION_DISABLED',
 'DETECTOR_INPUT_TOO_LARGE','DETECTOR_OUTPUT_TOO_LARGE','DETECTOR_TOOL_UNAVAILABLE','DETECTOR_TOOL_TIMEOUT',
 'DETECTOR_TOOL_EXIT','DETECTOR_INVALID_REPORT','DETECTOR_NORMALIZATION_INCOMPLETE','RESULT_PERSISTENCE_FAILED',
 'VALIDATION_DEADLINE_EXCEEDED','STAGE_NOT_OBSERVED') THEN value
 WHEN value IS NULL THEN NULL ELSE 'OPERATION_FAILED' END
$$;

ALTER TABLE secret_run_execution_events ADD CONSTRAINT ck_secret_execution_reason
 CHECK(reason_code IS NULL OR reason_code=secret_execution_safe_reason(reason_code));

CREATE FUNCTION secret_append_execution_event(
 target_run BIGINT,target_scope BIGINT,target_attempt INTEGER,target_generation BIGINT,
 target_stage TEXT,target_operation TEXT,target_outcome TEXT,target_http INTEGER,target_reason TEXT,
 target_processed BIGINT,target_total BIGINT,target_duration BIGINT,target_key TEXT,is_lifecycle BOOLEAN)
RETURNS BOOLEAN LANGUAGE plpgsql AS $$
DECLARE r secret_scan_runs%ROWTYPE; detail_count BIGINT;
BEGIN
 SELECT * INTO r FROM secret_scan_runs WHERE run_id=target_run FOR UPDATE;
 IF NOT FOUND OR r.execution_trace_version IS NULL OR r.execution_events_expired_at IS NOT NULL THEN RETURN false; END IF;
 IF target_scope IS NOT NULL AND NOT EXISTS(SELECT 1 FROM secret_run_scopes WHERE run_scope_id=target_scope AND run_id=target_run)
 THEN RAISE EXCEPTION 'EXECUTION_EVENT_SCOPE_MISMATCH' USING ERRCODE='23514'; END IF;
 IF EXISTS(SELECT 1 FROM secret_run_execution_events WHERE run_id=target_run AND event_key=target_key) THEN RETURN true; END IF;
 INSERT INTO secret_run_execution_stage_facts(run_id,attempt_no,stage,started_at,finished_at,completed_objects,completed_scopes)
 VALUES(target_run,target_attempt,target_stage,CASE WHEN target_outcome='STARTED' THEN clock_timestamp() END,
  CASE WHEN is_lifecycle AND target_outcome IN('COMPLETED','PARTIAL','FAILED','SKIPPED','CANCELLED') THEN clock_timestamp() END,
  CASE WHEN target_operation='GITLEAKS_SCAN' AND target_outcome='COMPLETED' THEN 1 ELSE 0 END,
  CASE WHEN target_operation='SCOPE_COLLECTION' AND target_outcome IN('COMPLETED','PARTIAL','FAILED','SKIPPED') THEN 1 ELSE 0 END)
 ON CONFLICT(run_id,attempt_no,stage) DO UPDATE SET
  started_at=COALESCE(secret_run_execution_stage_facts.started_at,excluded.started_at),
  finished_at=COALESCE(excluded.finished_at,secret_run_execution_stage_facts.finished_at),
  completed_objects=secret_run_execution_stage_facts.completed_objects+excluded.completed_objects,
  completed_scopes=secret_run_execution_stage_facts.completed_scopes+excluded.completed_scopes;
 SELECT count(*) INTO detail_count FROM secret_run_execution_events
 WHERE run_id=target_run AND attempt_no=target_attempt AND NOT lifecycle;
 IF r.execution_event_count>=2000 OR (NOT is_lifecycle AND (r.execution_event_count>=1872 OR detail_count>=1000)) THEN
  UPDATE secret_scan_runs SET execution_suppressed_count=execution_suppressed_count+1,
   execution_last_activity_at=clock_timestamp() WHERE run_id=target_run;
  RETURN true;
 END IF;
 INSERT INTO secret_run_execution_events(run_id,event_id,event_key,run_scope_id,attempt_no,lease_generation,
  stage,operation_code,outcome,http_status,reason_code,processed_count,total_count,duration_ms,lifecycle)
 VALUES(target_run,r.execution_event_count+1,target_key,target_scope,target_attempt,target_generation,
  target_stage,target_operation,target_outcome,target_http,secret_execution_safe_reason(target_reason),
  target_processed,target_total,target_duration,is_lifecycle);
 UPDATE secret_scan_runs SET execution_event_count=execution_event_count+1,execution_last_activity_at=clock_timestamp()
 WHERE run_id=target_run;
 RETURN true;
END $$;

CREATE FUNCTION secret_record_execution_event(
 target_job BIGINT,target_token UUID,target_generation BIGINT,target_scope BIGINT,
 target_stage TEXT,target_operation TEXT,target_outcome TEXT,target_http INTEGER,target_reason TEXT,
 target_processed BIGINT,target_total BIGINT,target_duration BIGINT,target_key TEXT)
RETURNS BOOLEAN LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE j secret_jobs%ROWTYPE; target_run BIGINT;
BEGIN
 SELECT * INTO j FROM secret_jobs WHERE job_id=target_job FOR UPDATE;
 IF NOT FOUND OR j.status<>'LEASED' OR j.lease_token IS DISTINCT FROM target_token
 OR j.lease_generation<>target_generation OR j.lease_until<=clock_timestamp() THEN RETURN false; END IF;
 SELECT run_id INTO target_run FROM secret_scan_runs WHERE job_id=target_job;
 IF target_run IS NULL OR EXISTS(SELECT 1 FROM secret_scan_runs WHERE run_id=target_run AND execution_trace_version IS NULL) THEN RETURN true; END IF;
 RETURN secret_append_execution_event(target_run,target_scope,j.attempt_no,j.lease_generation,
  target_stage,target_operation,target_outcome,target_http,target_reason,target_processed,target_total,target_duration,target_key,
  target_stage='RESULT' AND target_operation='STAGE_SUMMARY' AND target_outcome='STARTED');
END $$;

CREATE FUNCTION secret_execution_run_registered() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE j secret_jobs%ROWTYPE;
BEGIN
 IF NEW.execution_trace_version IS NULL THEN RETURN NEW; END IF;
 SELECT * INTO j FROM secret_jobs WHERE job_id=NEW.job_id;
 PERFORM secret_append_execution_event(NEW.run_id,NULL,0,0,'QUEUE','RUN_REGISTERED','STARTED',NULL,NULL,NULL,NULL,NULL,'registered',true);
 RETURN NEW;
END $$;
CREATE TRIGGER trg_secret_execution_run_registered AFTER INSERT ON secret_scan_runs
FOR EACH ROW EXECUTE FUNCTION secret_execution_run_registered();

CREATE FUNCTION secret_execution_job_transition() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE run BIGINT; op TEXT; outcome TEXT;
BEGIN
 IF NEW.status=OLD.status AND NEW.attempt_no=OLD.attempt_no THEN RETURN NEW; END IF;
 SELECT run_id INTO run FROM secret_scan_runs WHERE job_id=NEW.job_id;
 IF run IS NULL THEN RETURN NEW; END IF;
 IF NEW.status='LEASED' THEN op:='WORKER_CLAIM';outcome:='COMPLETED';
 ELSIF NEW.status='PENDING' AND OLD.status='LEASED' THEN op:='RUN_RETRY';outcome:='RETRY_SCHEDULED';
 ELSIF NEW.status='FAILED' THEN op:='RUN_FINISHED';outcome:='FAILED';
 ELSIF NEW.status='CANCELLED' THEN op:='RUN_FINISHED';outcome:='CANCELLED';
 ELSE RETURN NEW; END IF;
 PERFORM secret_append_execution_event(run,NULL,NEW.attempt_no,NEW.lease_generation,'QUEUE',op,outcome,
  NULL,NEW.last_error_code,NULL,NULL,NULL,op||':'||NEW.attempt_no,true);
 RETURN NEW;
END $$;
CREATE TRIGGER trg_secret_execution_job_transition AFTER UPDATE ON secret_jobs
FOR EACH ROW EXECUTE FUNCTION secret_execution_job_transition();

CREATE FUNCTION secret_execution_scope_transition() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE j secret_jobs%ROWTYPE; outcome TEXT;
BEGIN
 IF NEW.collection_status=OLD.collection_status THEN RETURN NEW; END IF;
 SELECT jobs.* INTO j FROM secret_scan_runs r JOIN secret_jobs jobs USING(job_id) WHERE r.run_id=NEW.run_id;
 IF j.status<>'LEASED' OR j.lease_until<=clock_timestamp() THEN RETURN NEW; END IF;
 outcome:=CASE NEW.collection_status WHEN 'RUNNING' THEN 'STARTED' WHEN 'SUCCEEDED' THEN 'COMPLETED'
  WHEN 'PARTIAL' THEN 'PARTIAL' WHEN 'FAILED' THEN 'FAILED' WHEN 'SKIPPED' THEN 'SKIPPED' ELSE NULL END;
 IF outcome IS NOT NULL THEN
 PERFORM secret_append_execution_event(NEW.run_id,NEW.run_scope_id,j.attempt_no,j.lease_generation,
  'COLLECTION','SCOPE_COLLECTION',outcome,NULL,NEW.failure_code,NEW.object_count,NULL,
  CASE WHEN NEW.finished_at IS NOT NULL AND NEW.started_at IS NOT NULL THEN LEAST(86400000,GREATEST(0,(extract(epoch FROM NEW.finished_at-NEW.started_at)*1000)::bigint)) ELSE NULL END,
  'scope:'||NEW.run_scope_id||':'||j.attempt_no||':'||outcome,false);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER trg_secret_execution_scope_transition AFTER UPDATE ON secret_run_scopes
FOR EACH ROW EXECUTE FUNCTION secret_execution_scope_transition();

CREATE FUNCTION secret_execution_validation_transition() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE j secret_jobs%ROWTYPE; scope BIGINT; op TEXT; outcome TEXT;
BEGIN
 IF NEW.evidence_version<>1 OR (TG_OP='UPDATE' AND NEW.attempt_state=OLD.attempt_state) THEN RETURN NEW; END IF;
 SELECT * INTO j FROM secret_jobs WHERE job_id=NEW.job_id;
 IF j.status<>'LEASED' OR j.lease_until<=clock_timestamp() OR j.lease_generation<>NEW.reservation_generation
 OR j.attempt_no<>NEW.attempt_no THEN RETURN NEW; END IF;
 SELECT run_scope_id INTO scope FROM secret_run_scopes WHERE run_id=NEW.run_id AND scope_id=NEW.scope_id;
 op:=CASE NEW.endpoint_class WHEN 'GITHUB_USER' THEN 'GITHUB_CREDENTIAL_CHECK'
  WHEN 'NOTION_SELF' THEN 'NOTION_CREDENTIAL_CHECK' WHEN 'AWS_STS' THEN 'AWS_CREDENTIAL_CHECK' ELSE 'CREDENTIAL_CHECK' END;
 outcome:=CASE NEW.attempt_state WHEN 'SENT' THEN 'STARTED' WHEN 'COMPLETED' THEN
  CASE WHEN NEW.result='UNCHECKED' THEN 'SKIPPED' WHEN NEW.result IN('VALID','INVALID') THEN 'COMPLETED' ELSE 'PARTIAL' END
  WHEN 'ABANDONED' THEN 'FAILED' ELSE NULL END;
 IF outcome IS NOT NULL THEN
 PERFORM secret_append_execution_event(NEW.run_id,scope,j.attempt_no,j.lease_generation,'VALIDATION',op,outcome,
  NEW.http_status,NEW.reason_code,CASE WHEN NEW.attempt_state='COMPLETED' THEN 1 ELSE NULL END,NULL,
  CASE WHEN NEW.completed_at IS NOT NULL AND NEW.request_sent_at IS NOT NULL THEN LEAST(86400000,GREATEST(0,(extract(epoch FROM NEW.completed_at-NEW.request_sent_at)*1000)::bigint)) ELSE NULL END,
  'validation:'||NEW.attempt_id||':'||NEW.attempt_state,false);
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER trg_secret_execution_validation_transition AFTER INSERT OR UPDATE ON secret_validation_attempts
FOR EACH ROW EXECUTE FUNCTION secret_execution_validation_transition();

-- Worker finalization changes are observed in the same transaction as reconciliation.
CREATE FUNCTION secret_execution_run_terminal() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE j secret_jobs%ROWTYPE; stage_name TEXT; value TEXT; outcome TEXT; reason TEXT; total BIGINT; done BIGINT;
BEGIN
 IF NEW.result_status=OLD.result_status OR NEW.result_status NOT IN('SUCCEEDED','PARTIAL','FAILED','SKIPPED') THEN RETURN NEW; END IF;
 SELECT * INTO j FROM secret_jobs WHERE job_id=NEW.job_id;
 SELECT count(*),count(*) FILTER(WHERE collection_status IN('SUCCEEDED','PARTIAL','FAILED','SKIPPED')) INTO total,done
 FROM secret_run_scopes WHERE run_id=NEW.run_id;
 FOREACH stage_name IN ARRAY ARRAY['COLLECTION','DETECTION','VALIDATION','RESULT'] LOOP
  value:=CASE stage_name WHEN 'COLLECTION' THEN NEW.collection_status WHEN 'DETECTION' THEN NEW.detection_status
   WHEN 'VALIDATION' THEN NEW.validation_status ELSE NEW.result_status END;
  IF value NOT IN('SUCCEEDED','PARTIAL','FAILED','SKIPPED') THEN CONTINUE; END IF;
  outcome:=CASE value WHEN 'SUCCEEDED' THEN 'COMPLETED' ELSE value END;
  reason:=NEW.failure_code;
  IF value='SUCCEEDED' AND stage_name IN('COLLECTION','DETECTION','VALIDATION')
   AND NOT EXISTS(SELECT 1 FROM secret_run_execution_stage_facts f
    WHERE f.run_id=NEW.run_id AND f.attempt_no=j.attempt_no AND f.stage=stage_name AND f.started_at IS NOT NULL)
  THEN outcome:='SKIPPED';reason:='STAGE_NOT_OBSERVED'; END IF;
  IF value='SKIPPED' THEN
   SELECT CASE WHEN bool_and(right(snapshot_content_type,9)='_METADATA') THEN 'NOT_APPLICABLE_METADATA'
    WHEN stage_name='DETECTION' AND COALESCE(sum(object_count),0)=0 THEN 'NO_OBJECTS'
    ELSE min(CASE WHEN stage_name='VALIDATION' THEN validation_reason_code ELSE detection_reason_code END) END
    INTO reason FROM secret_run_scopes WHERE run_id=NEW.run_id;
  END IF;
  PERFORM secret_append_execution_event(NEW.run_id,NULL,j.attempt_no,j.lease_generation,stage_name,
   CASE WHEN stage_name='RESULT' THEN 'RUN_FINISHED' ELSE 'STAGE_SUMMARY' END,outcome,NULL,reason,
   CASE WHEN stage_name='COLLECTION' THEN done ELSE NULL END,CASE WHEN stage_name='COLLECTION' THEN total ELSE NULL END,
   NULL,'summary:'||j.attempt_no||':'||stage_name,true);
 END LOOP;
 RETURN NEW;
END $$;
CREATE TRIGGER trg_secret_execution_run_terminal AFTER UPDATE OF result_status ON secret_scan_runs
FOR EACH ROW EXECUTE FUNCTION secret_execution_run_terminal();

CREATE INDEX idx_secret_execution_expiry ON secret_scan_runs(finished_at,run_id)
 WHERE execution_trace_version=1 AND execution_events_expired_at IS NULL;
CREATE FUNCTION secret_purge_execution_events() RETURNS BIGINT LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE removed BIGINT;
BEGIN
 WITH candidates AS(SELECT run_id FROM secret_scan_runs
 WHERE execution_trace_version=1 AND execution_events_expired_at IS NULL AND finished_at<clock_timestamp()-interval '30 days'
 ORDER BY finished_at,run_id LIMIT 100 FOR UPDATE SKIP LOCKED),
 expired AS(UPDATE secret_scan_runs r SET execution_events_expired_at=clock_timestamp() FROM candidates c WHERE r.run_id=c.run_id
 RETURNING r.run_id), deleted AS(DELETE FROM secret_run_execution_events e USING expired x WHERE e.run_id=x.run_id RETURNING 1)
 SELECT count(*) INTO removed FROM deleted;
 RETURN removed;
END $$;


-- Read ALL does not alter actual provenance. UNCLASSIFIED cases preserve the registered source origin.
ALTER TABLE secret_response_cases DROP CONSTRAINT secret_response_cases_case_origin_check;
ALTER TABLE secret_response_cases ADD CONSTRAINT secret_response_cases_case_origin_check CHECK (case_origin IN ('PRODUCTION','TEST','UNCLASSIFIED'));
ALTER TABLE secret_scope_origin_decisions DROP CONSTRAINT secret_scope_origin_decisions_to_origin_check;
ALTER TABLE secret_scope_origin_decisions ADD CONSTRAINT secret_scope_origin_decisions_to_origin_check CHECK (to_origin IN ('PRODUCTION','TEST','UNCLASSIFIED'));
ALTER TABLE secret_scope_classification_proposals DROP CONSTRAINT secret_scope_classification_proposals_proposed_origin_check;
ALTER TABLE secret_scope_classification_proposals ADD CONSTRAINT secret_scope_classification_proposals_proposed_origin_check CHECK (proposed_origin IN ('PRODUCTION','TEST','UNCLASSIFIED'));
ALTER TABLE secret_credential_lifecycle_evidence DROP CONSTRAINT secret_credential_lifecycle_evidence_origin_check;
ALTER TABLE secret_credential_lifecycle_evidence ADD CONSTRAINT secret_credential_lifecycle_evidence_origin_check CHECK (origin IN ('PRODUCTION','TEST','UNCLASSIFIED'));
ALTER TABLE secret_lifecycle_evidence_applications DROP CONSTRAINT secret_lifecycle_evidence_applications_origin_check;
ALTER TABLE secret_lifecycle_evidence_applications ADD CONSTRAINT secret_lifecycle_evidence_applications_origin_check CHECK (origin IN ('PRODUCTION','TEST','UNCLASSIFIED'));
ALTER TABLE secret_case_resolution_checks DROP CONSTRAINT secret_case_resolution_checks_target_origin_check;
ALTER TABLE secret_case_resolution_checks ADD CONSTRAINT secret_case_resolution_checks_target_origin_check CHECK (target_origin IN ('PRODUCTION','TEST','UNCLASSIFIED'));

-- Classification provenance remains nullable for UNCLASSIFIED; approval actors/times are in the append-only decision ledger.
-- Policy-only UNCLASSIFIED proposals may retain this origin, never reclassify another origin to it.
CREATE FUNCTION secret_guard_unclassified_proposal() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.proposed_origin='UNCLASSIFIED' AND NOT EXISTS(
   SELECT 1 FROM secret_connection_scopes s WHERE s.scope_id=NEW.scope_id
    AND s.response_origin='UNCLASSIFIED' AND s.response_origin_version=NEW.expected_scope_version
    AND s.revision=NEW.scope_revision
    AND md5(jsonb_build_array(s.content_type,s.approved_ref,s.history_limit)::text)=NEW.scope_fingerprint
 ) THEN RAISE EXCEPTION 'UNCLASSIFIED proposal must preserve the current registered source'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER secret_unclassified_proposal_guard BEFORE INSERT OR UPDATE OF proposed_origin,scope_id,expected_scope_version,scope_revision,scope_fingerprint
 ON secret_scope_classification_proposals FOR EACH ROW EXECUTE FUNCTION secret_guard_unclassified_proposal();

CREATE OR REPLACE VIEW secret_scope_governance_status AS
WITH basis AS (
 SELECT s.*, b.binding_id,b.policy_id,b.policy_version,p.status AS policy_status,p.valid_from,p.valid_until,
   EXISTS(SELECT 1 FROM secret_scope_classification_proposals q WHERE q.scope_id=s.scope_id AND q.status='PENDING_APPROVAL') AS pending,
   EXISTS(SELECT 1 FROM secret_scope_origin_decisions d WHERE d.scope_id=s.scope_id AND d.version=s.response_origin_version AND d.decision='APPROVED') AS decided,
   EXISTS(SELECT 1 FROM secret_storage_policy_rules r WHERE r.policy_id=b.policy_id AND r.policy_version=b.policy_version
     AND r.scope_id=s.scope_id AND r.scope_revision=s.revision AND r.scope_fingerprint=md5(jsonb_build_array(s.content_type,s.approved_ref,s.history_limit)::text)) AS policy_matches,
   EXISTS(SELECT 1 FROM secret_scope_classification_impacts i JOIN secret_response_cases c ON c.case_id=i.case_id
     JOIN secret_scope_origin_decisions d ON d.decision_id=i.decision_id
     WHERE d.scope_id=s.scope_id AND d.version=s.response_origin_version AND i.previous_origin<>i.new_origin
       AND c.is_current AND c.action_status<>'RESOLVED' AND c.case_origin<>s.response_origin) AS impact_pending
 FROM secret_connection_scopes s
 LEFT JOIN secret_scope_policy_bindings b ON b.scope_id=s.scope_id AND b.effective_until IS NULL
 LEFT JOIN secret_storage_policies p ON p.policy_id=b.policy_id AND p.version=b.policy_version
), reasons AS (
 SELECT scope_id,array_remove(ARRAY[
   CASE WHEN pending THEN 'PENDING_REVIEW' END,
   CASE WHEN impact_pending THEN 'CLASSIFICATION_IMPACT_PENDING' END,
   CASE WHEN content_type IN ('GITHUB_REPOSITORY_FILES','AWS_SECRETS_MANAGER_VALUE','AWS_SSM_PARAMETER_VALUE','AWS_S3_OBJECT_CONTENT','NOTION_PAGE_CONTENT') THEN
     CASE WHEN binding_id IS NULL THEN 'POLICY_MISSING'
       WHEN policy_status<>'ACTIVE' THEN 'POLICY_RETIRED'
       WHEN valid_from>now() THEN 'POLICY_NOT_YET_VALID'
       WHEN valid_until<=now() THEN 'POLICY_EXPIRED'
       WHEN NOT policy_matches THEN 'POLICY_SCOPE_MISMATCH' END END
 ],NULL)::text[] AS setup_reason_codes FROM basis
)
SELECT scope_id,cardinality(setup_reason_codes)>0 AS needs_review,setup_reason_codes FROM reasons;

-- The page-wide rule covers only title and local blocks of the approved page.
CREATE OR REPLACE VIEW secret_occurrence_policy_results AS
WITH scope_basis AS (
    SELECT o.occurrence_id,o.scope_id,o.source_object_ref,o.exposure_status,
           o.policy_assessed_binding_id,o.policy_assessed_origin_version,o.policy_recheck_required,
           s.connection_id,s.revision,s.response_origin,s.response_origin_version,s.enabled,
           s.content_type,s.history_limit,s.approved_ref,
           md5(jsonb_build_array(s.content_type,s.approved_ref,s.history_limit)::text) AS fingerprint,
           regexp_match(s.approved_ref,'^github://([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+)/([^/?#]+)/(.+/)$') AS github,
           b.binding_id,b.scope_revision AS bound_revision,b.scope_origin_version AS bound_origin_version,
           b.scope_fingerprint AS bound_fingerprint,b.policy_id,b.policy_version,
           p.status,p.valid_from,p.valid_until
    FROM secret_occurrences o
    JOIN secret_connection_scopes s ON s.scope_id=o.scope_id
    LEFT JOIN secret_scope_policy_bindings b ON b.scope_id=s.scope_id
        AND b.effective_until IS NULL AND b.effective_from <= now()
    LEFT JOIN secret_storage_policies p ON p.policy_id=b.policy_id AND p.version=b.policy_version
), matched AS (
    SELECT basis.*,
        COALESCE(rules.allow_count,0) AS allow_count,COALESCE(rules.deny_count,0) AS deny_count
    FROM scope_basis basis
    LEFT JOIN LATERAL (
        SELECT COUNT(*) FILTER (WHERE r.effect='ALLOW') AS allow_count,
               COUNT(*) FILTER (WHERE r.effect='DENY') AS deny_count
        FROM secret_storage_policy_rules r
        WHERE r.policy_id=basis.policy_id AND r.policy_version=basis.policy_version
          AND r.connection_id=basis.connection_id AND r.scope_id=basis.scope_id
          AND r.scope_revision=basis.revision AND r.scope_fingerprint=basis.fingerprint
          AND r.content_type=basis.content_type
          AND (
              (basis.content_type='GITHUB_REPOSITORY_FILES' AND basis.history_limit='CURRENT_COMMIT_ONLY'
               AND basis.github IS NOT NULL
               AND starts_with(basis.source_object_ref,basis.github[1] || '/' || basis.github[2] || '/' || basis.github[4])
               AND basis.source_object_ref !~ '(^|/)\.\.(/|$)'
               AND (r.path_match='SCOPE' OR
                    (r.branch_condition=basis.github[3] AND (
                        (r.path_match='EXACT' AND basis.source_object_ref=basis.github[1] || '/' || basis.github[2] || '/' || r.protected_path_condition)
                        OR (r.path_match='PREFIX' AND starts_with(basis.source_object_ref,basis.github[1] || '/' || basis.github[2] || '/' || r.protected_path_condition))
                    ))))
              OR (basis.content_type IN ('AWS_SECRETS_MANAGER_VALUE','AWS_SSM_PARAMETER_VALUE','AWS_S3_OBJECT_CONTENT')
                  AND basis.history_limit='CURRENT_VALUE_ONLY' AND r.path_match='SCOPE'
                  AND basis.approved_ref ~ '^aws://[0-9]{12}/[a-z0-9-]+/(secrets-manager/secret|ssm/parameter|s3/object)/[^?#*]+$'
                  AND basis.source_object_ref='aws-content-scope:' || basis.scope_id::text)
              OR (basis.content_type='NOTION_PAGE_CONTENT' AND basis.history_limit='CURRENT_VERSION_ONLY'
                  AND r.path_match='SCOPE'
                  AND basis.approved_ref ~ '^notion://pages/([0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$'
                  AND basis.source_object_ref ~ '^notion/pages/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/(title|blocks/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$'
                  AND replace(split_part(basis.approved_ref,'/',4),'-','')
                      =replace(split_part(basis.source_object_ref,'/',3),'-',''))
          )
    ) rules ON true
), evaluated AS (
    SELECT matched.*,
       CASE WHEN content_type IN ('IAM_ACCESS_KEY_METADATA','AWS_SECRETS_MANAGER_METADATA','AWS_SSM_PARAMETER_METADATA','AWS_S3_BUCKET_METADATA') THEN 'METADATA_NOT_APPLICABLE'
            WHEN binding_id IS NULL THEN 'NO_ACTIVE_BINDING'
            WHEN NOT enabled OR (response_origin='UNCLASSIFIED' AND NOT EXISTS(SELECT 1 FROM secret_scope_origin_decisions approved
              WHERE approved.scope_id=matched.scope_id AND approved.version=matched.response_origin_version
                AND approved.decision='APPROVED')) THEN 'SCOPE_NOT_APPROVED'
            WHEN bound_revision<>revision OR bound_origin_version<>response_origin_version OR bound_fingerprint<>fingerprint THEN 'SCOPE_CHANGED'
            WHEN status<>'ACTIVE' THEN 'POLICY_RETIRED'
            WHEN now()<valid_from THEN 'POLICY_NOT_YET_VALID'
            WHEN valid_until IS NOT NULL AND now()>=valid_until THEN 'POLICY_EXPIRED'
            WHEN allow_count>0 AND deny_count>0 THEN 'POLICY_CONFLICT'
            WHEN allow_count>0 THEN 'EXPLICIT_ALLOW'
            WHEN deny_count>0 THEN 'EXPLICIT_DENY'
            ELSE 'NO_MATCHING_RULE' END AS reason_code
    FROM matched
)
SELECT occurrence_id,scope_id,binding_id,policy_id,policy_version,reason_code,
       CASE reason_code WHEN 'EXPLICIT_ALLOW' THEN 'ALLOWED' WHEN 'EXPLICIT_DENY' THEN 'DENIED' ELSE 'UNKNOWN' END::varchar(10) AS policy_result,
       (policy_recheck_required OR (exposure_status<>'UNKNOWN' AND (
           policy_assessed_binding_id IS DISTINCT FROM binding_id
           OR policy_assessed_origin_version IS DISTINCT FROM response_origin_version
           OR (binding_id IS NOT NULL AND reason_code NOT IN ('EXPLICIT_ALLOW','EXPLICIT_DENY'))
       ))) AS requires_reassessment
FROM evaluated;


REVOKE EXECUTE ON FUNCTION secret_append_execution_event(bigint,bigint,integer,bigint,text,text,text,integer,text,bigint,bigint,bigint,text,boolean) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION secret_record_execution_event(bigint,uuid,bigint,bigint,text,text,text,integer,text,bigint,bigint,bigint,text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION secret_purge_execution_events() FROM PUBLIC;
-- A caller must not attach these privileged trigger functions to a forged temporary table.
REVOKE EXECUTE ON FUNCTION secret_execution_run_registered(),secret_execution_job_transition(),
 secret_execution_scope_transition(),secret_execution_validation_transition(),secret_execution_run_terminal() FROM PUBLIC;
