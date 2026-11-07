-- Usage is an independent observation. It never asserts severity-v2 abuse or a scan run.
ALTER TABLE secret_credential_sets ADD COLUMN aws_key_id_fingerprint BYTEA
 CHECK(aws_key_id_fingerprint IS NULL OR (issuer='AWS' AND octet_length(aws_key_id_fingerprint)=32));
CREATE FUNCTION secret_usage_key_identity_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF (OLD.component_state,OLD.fingerprint,OLD.candidate_locator,OLD.fingerprint_key_version,OLD.issuer,OLD.credential_type)
 IS DISTINCT FROM (NEW.component_state,NEW.fingerprint,NEW.candidate_locator,NEW.fingerprint_key_version,NEW.issuer,NEW.credential_type)
 AND NEW.aws_key_id_fingerprint IS NOT DISTINCT FROM OLD.aws_key_id_fingerprint
 THEN NEW.aws_key_id_fingerprint:=NULL; END IF;
 IF OLD.external_key_ref IS DISTINCT FROM NEW.external_key_ref
 THEN NEW.credential_revision:=GREATEST(OLD.credential_revision+1,NEW.credential_revision); END IF;
 RETURN NEW; END $$;
CREATE TRIGGER secret_usage_key_identity_guard BEFORE UPDATE ON secret_credential_sets
 FOR EACH ROW EXECUTE FUNCTION secret_usage_key_identity_guard();
ALTER TABLE secret_jobs DROP CONSTRAINT ck_secret_job_purpose;
ALTER TABLE secret_jobs ADD CONSTRAINT ck_secret_job_purpose CHECK(
 (kind='FULL_SCAN' AND purpose='COLLECTION_AND_DETECTION') OR
 (kind='REVALIDATE' AND purpose IN('LOCATION_RECHECK','CREDENTIAL_VALIDITY')) OR
 (kind='ASSESS' AND purpose='SEVERITY_ASSESSMENT') OR
 (kind='ENRICH' AND purpose IN('PERMISSION_ASSISTANCE','USAGE_OBSERVATION')));
DROP INDEX uq_secret_permission_active;
CREATE UNIQUE INDEX uq_secret_permission_active ON secret_jobs(target_occurrence_id)
 WHERE purpose='PERMISSION_ASSISTANCE' AND status IN('PENDING','LEASED');
CREATE UNIQUE INDEX uq_secret_usage_active ON secret_jobs(target_occurrence_id)
 WHERE purpose='USAGE_OBSERVATION' AND status IN('PENDING','LEASED');

-- Operator registration, not a public arbitrary-account/region API. Every target is explicitly approved.
CREATE TABLE secret_usage_targets (
 target_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 occurrence_id BIGINT NOT NULL REFERENCES secret_occurrences,
 collector_connection_id BIGINT NOT NULL REFERENCES secret_connections,
 collector_scope_id BIGINT NOT NULL REFERENCES secret_connection_scopes,
 account_ref VARCHAR(12) NOT NULL CHECK(account_ref ~ '^[0-9]{12}$'),
 region VARCHAR(40) NOT NULL CHECK(region ~ '^[a-z]{2}(-[a-z]+)+-[0-9]$'),
 credential_revision BIGINT NOT NULL,
 scope_revision BIGINT NOT NULL,
 source_scope_version BIGINT NOT NULL,
 collector_scope_version BIGINT NOT NULL,
 collector_scope_revision BIGINT NOT NULL,
 collector_auth_ref VARCHAR(500) NOT NULL,
 collector_approved_ref VARCHAR(500) NOT NULL,
 approved_by_user_id BIGINT NOT NULL REFERENCES dashboard_users,
 approved_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 revision BIGINT NOT NULL DEFAULT 1 CHECK(revision>0),
 enabled BOOLEAN NOT NULL DEFAULT false,
 schedule_enabled BOOLEAN NOT NULL DEFAULT false,
 next_scheduled_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(occurrence_id,collector_connection_id,account_ref,region)
);
CREATE INDEX idx_secret_usage_due ON secret_usage_targets(next_scheduled_at,target_id)
 WHERE enabled AND schedule_enabled;
CREATE TABLE secret_usage_requests (
 request_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 job_id BIGINT NOT NULL UNIQUE REFERENCES secret_jobs,
 target_id BIGINT NOT NULL REFERENCES secret_usage_targets,
 occurrence_id BIGINT NOT NULL REFERENCES secret_occurrences,
 credential_set_id BIGINT NOT NULL REFERENCES secret_credential_sets,
 credential_revision BIGINT NOT NULL,
 scope_revision BIGINT NOT NULL,
 requested_by_user_id BIGINT NOT NULL REFERENCES dashboard_users,
 trigger_type VARCHAR(12) NOT NULL CHECK(trigger_type IN('MANUAL','SCHEDULED')),
 source_context_version VARCHAR(64) NOT NULL CHECK(source_context_version ~ '^[a-f0-9]{64}$'),
 baseline JSONB NOT NULL CHECK(jsonb_typeof(baseline)='object' AND octet_length(baseline::text)<=8192),
 window_start TIMESTAMPTZ NOT NULL,
 window_end TIMESTAMPTZ NOT NULL,
 available_from TIMESTAMPTZ,
 status VARCHAR(20) NOT NULL DEFAULT 'PENDING' CHECK(status IN('PENDING','RUNNING','COMPLETE','PARTIAL','UNAVAILABLE','CANCELLED')),
 observation_status VARCHAR(30) CHECK(observation_status IN('OBSERVED','NOT_OBSERVED_IN_SCOPE','UNAVAILABLE')),
 coverage_status VARCHAR(12) NOT NULL DEFAULT 'UNKNOWN' CHECK(coverage_status IN('COMPLETE','PARTIAL','UNKNOWN')),
 binding_level VARCHAR(20) NOT NULL DEFAULT 'UNRESOLVED' CHECK(binding_level IN('EXACT_CREDENTIAL','PRINCIPAL_ONLY','UNRESOLVED')),
 reason_codes TEXT[] NOT NULL DEFAULT '{}',
 page_count INT NOT NULL DEFAULT 0 CHECK(page_count BETWEEN 0 AND 100),
 event_count INT NOT NULL DEFAULT 0 CHECK(event_count BETWEEN 0 AND 5000),
 requested_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 started_at TIMESTAMPTZ,
 completed_at TIMESTAMPTZ,
 CHECK(window_end>window_start AND window_end-window_start<=interval '90 days'),
 CHECK(observation_status IS DISTINCT FROM 'NOT_OBSERVED_IN_SCOPE' OR
       (status='COMPLETE' AND coverage_status='COMPLETE' AND binding_level='EXACT_CREDENTIAL' AND event_count=0))
);
CREATE INDEX idx_secret_usage_request_occurrence ON secret_usage_requests(occurrence_id,request_id DESC);
CREATE FUNCTION secret_usage_request_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP='UPDATE' AND (OLD.job_id,OLD.target_id,OLD.occurrence_id,OLD.credential_set_id,OLD.credential_revision,OLD.scope_revision,OLD.requested_by_user_id,OLD.trigger_type,OLD.source_context_version,OLD.baseline,OLD.window_start,OLD.window_end,OLD.requested_at)
 IS DISTINCT FROM (NEW.job_id,NEW.target_id,NEW.occurrence_id,NEW.credential_set_id,NEW.credential_revision,NEW.scope_revision,NEW.requested_by_user_id,NEW.trigger_type,NEW.source_context_version,NEW.baseline,NEW.window_start,NEW.window_end,NEW.requested_at)
 THEN RAISE EXCEPTION 'USAGE_REQUEST_BASELINE_IMMUTABLE' USING ERRCODE='23514'; END IF;
 IF TG_OP='INSERT' AND NOT EXISTS(SELECT 1 FROM secret_jobs j JOIN secret_usage_targets t ON t.target_id=NEW.target_id
 JOIN secret_occurrences o ON o.occurrence_id=NEW.occurrence_id
 WHERE j.job_id=NEW.job_id AND j.purpose='USAGE_OBSERVATION' AND j.target_occurrence_id=NEW.occurrence_id
 AND t.occurrence_id=NEW.occurrence_id AND o.credential_set_id=NEW.credential_set_id)
 THEN RAISE EXCEPTION 'USAGE_REQUEST_PARENT' USING ERRCODE='23514'; END IF;
 RETURN NEW; END $$;
CREATE TRIGGER trg_secret_usage_request_guard BEFORE INSERT OR UPDATE ON secret_usage_requests
 FOR EACH ROW EXECUTE FUNCTION secret_usage_request_guard();
CREATE TABLE secret_usage_observations (
 observation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 source_kind VARCHAR(10) NOT NULL CHECK(source_kind IN('PROVIDER','MANUAL')),
 request_id BIGINT REFERENCES secret_usage_requests,
 occurrence_id BIGINT NOT NULL REFERENCES secret_occurrences,
 credential_set_id BIGINT NOT NULL REFERENCES secret_credential_sets,
 credential_revision BIGINT NOT NULL,
 scope_revision BIGINT NOT NULL,
 collector_connection_id BIGINT REFERENCES secret_connections,
 account_ref VARCHAR(12) CHECK(account_ref ~ '^[0-9]{12}$'),
 region VARCHAR(40),
 provider_event_id UUID,
 submitted_by_user_id BIGINT REFERENCES dashboard_users,
 source_context_version VARCHAR(64) NOT NULL CHECK(source_context_version ~ '^[a-f0-9]{64}$'),
 binding_level VARCHAR(20) NOT NULL CHECK(binding_level IN('EXACT_CREDENTIAL','PRINCIPAL_ONLY','UNRESOLVED')),
 coverage_status VARCHAR(12) NOT NULL CHECK(coverage_status IN('COMPLETE','PARTIAL','UNKNOWN')),
 action_code VARCHAR(30) NOT NULL CHECK(action_code IN('API_CALL','RESOURCE_READ','RESOURCE_CHANGE','AUTHENTICATION','UNKNOWN')),
 action_result VARCHAR(10) NOT NULL CHECK(action_result IN('SUCCESS','FAILURE','UNKNOWN')),
 actor_attribution VARCHAR(20) NOT NULL CHECK(actor_attribution IN('OWN_VALIDATION','EXPECTED_WORKLOAD','UNATTRIBUTED')),
 service_code VARCHAR(30) NOT NULL DEFAULT 'UNKNOWN' CHECK(service_code IN('IAM','STS','EC2','S3','KMS','SSM','SECRETS_MANAGER','CLOUDTRAIL','OTHER','UNKNOWN')),
 operation_code VARCHAR(50) NOT NULL DEFAULT 'UNKNOWN' CHECK(operation_code IN('UNKNOWN','GetCallerIdentity','AssumeRole','GetSessionToken','GetFederationToken','CreateAccessKey','UpdateAccessKey','DeleteAccessKey','ListAccessKeys','GetAccessKeyLastUsed','GetUser','ListUsers','AttachUserPolicy','DetachUserPolicy','PutUserPolicy','CreateUser','DeleteUser','CreateRole','DeleteRole','AttachRolePolicy','PutRolePolicy','ListBuckets','GetBucketPolicy','PutBucketPolicy','DeleteBucketPolicy','CreateBucket','DeleteBucket','DescribeInstances','RunInstances','TerminateInstances','AuthorizeSecurityGroupIngress','RevokeSecurityGroupIngress','GetSecretValue','PutSecretValue','DeleteSecret','DescribeSecret','GetParameter','GetParameters','PutParameter','DeleteParameter','Decrypt','Encrypt','GenerateDataKey','GetFunction','UpdateFunctionCode','LookupEvents','StopLogging','DeleteTrail')),
 source_ref_type VARCHAR(30), source_ref_id BIGINT,
 target_ref_type VARCHAR(20), target_ref_id BIGINT,
 validation_attempt_id BIGINT REFERENCES secret_validation_attempts,
 event_at TIMESTAMPTZ NOT NULL,
 window_start TIMESTAMPTZ NOT NULL,
 window_end TIMESTAMPTZ NOT NULL,
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 CHECK(window_end>window_start AND event_at>=window_start AND event_at<=window_end),
 CHECK(((source_kind='PROVIDER' AND request_id IS NOT NULL AND collector_connection_id IS NOT NULL
       AND account_ref IS NOT NULL AND region IS NOT NULL AND provider_event_id IS NOT NULL
       AND submitted_by_user_id IS NULL AND source_ref_type IS NULL AND source_ref_id IS NULL)
    OR (source_kind='MANUAL' AND request_id IS NULL AND collector_connection_id IS NULL
       AND account_ref IS NULL AND region IS NULL AND provider_event_id IS NULL
       AND submitted_by_user_id IS NOT NULL AND binding_level<>'EXACT_CREDENTIAL'
       AND source_ref_type IN('INVESTIGATION_HISTORY','ACTION_RECORD') AND source_ref_id IS NOT NULL
       AND target_ref_type IN('APPROVED_SCOPE','ASSET') AND target_ref_id IS NOT NULL
       AND actor_attribution<>'OWN_VALIDATION')) IS TRUE),
 CHECK(actor_attribution<>'OWN_VALIDATION' OR validation_attempt_id IS NOT NULL)
);
CREATE UNIQUE INDEX uq_secret_usage_provider_event ON secret_usage_observations
 (occurrence_id,credential_set_id,credential_revision,source_context_version,collector_connection_id,account_ref,region,provider_event_id)
 WHERE source_kind='PROVIDER';
CREATE INDEX idx_secret_usage_observation_occurrence ON secret_usage_observations(occurrence_id,event_at DESC,observation_id DESC);
CREATE TABLE secret_usage_decisions (
 decision_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 observation_id BIGINT NOT NULL REFERENCES secret_usage_observations,
 observation_revision BIGINT NOT NULL CHECK(observation_revision>0),
 actor_user_id BIGINT NOT NULL REFERENCES dashboard_users,
 decision VARCHAR(10) NOT NULL CHECK(decision IN('ACCEPT','REJECT','WITHDRAW')),
 reason_code VARCHAR(40) NOT NULL CHECK(reason_code IN('REVIEWED_USAGE','INSUFFICIENT_EVIDENCE','IDENTITY_MISMATCH','WITHDRAWN_BY_REVIEWER')),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 CHECK((decision='ACCEPT' AND reason_code='REVIEWED_USAGE') OR
       (decision='REJECT' AND reason_code IN('INSUFFICIENT_EVIDENCE','IDENTITY_MISMATCH')) OR
       (decision='WITHDRAW' AND reason_code='WITHDRAWN_BY_REVIEWER')),
 UNIQUE(observation_id,observation_revision)
);
CREATE FUNCTION secret_usage_observation_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.source_kind='PROVIDER' AND NOT EXISTS(SELECT 1 FROM secret_usage_requests r JOIN secret_usage_targets t USING(target_id)
 WHERE r.request_id=NEW.request_id AND r.occurrence_id=NEW.occurrence_id AND r.credential_set_id=NEW.credential_set_id
 AND r.credential_revision=NEW.credential_revision AND r.scope_revision=NEW.scope_revision
 AND r.source_context_version=NEW.source_context_version AND t.collector_connection_id=NEW.collector_connection_id
 AND t.account_ref=NEW.account_ref AND t.region=NEW.region AND r.window_start=NEW.window_start AND r.window_end=NEW.window_end)
 THEN RAISE EXCEPTION 'USAGE_OBSERVATION_PARENT' USING ERRCODE='23514'; END IF;
 RETURN NEW; END $$;
CREATE TRIGGER trg_secret_usage_observation_guard BEFORE INSERT ON secret_usage_observations
 FOR EACH ROW EXECUTE FUNCTION secret_usage_observation_guard();
CREATE FUNCTION secret_usage_decision_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 PERFORM observation_id FROM secret_usage_observations WHERE observation_id=NEW.observation_id FOR UPDATE;
 IF NOT EXISTS(SELECT 1 FROM secret_usage_observations WHERE observation_id=NEW.observation_id AND source_kind='MANUAL')
 OR NEW.observation_revision<>(SELECT COALESCE(max(observation_revision),0)+1 FROM secret_usage_decisions WHERE observation_id=NEW.observation_id)
 THEN RAISE EXCEPTION 'USAGE_DECISION_PARENT_OR_REVISION' USING ERRCODE='23514'; END IF;
 RETURN NEW; END $$;
CREATE TRIGGER trg_secret_usage_decision_guard BEFORE INSERT ON secret_usage_decisions
 FOR EACH ROW EXECUTE FUNCTION secret_usage_decision_guard();
CREATE FUNCTION secret_usage_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 RAISE EXCEPTION 'USAGE_HISTORY_IMMUTABLE' USING ERRCODE='23514'; END $$;
CREATE TRIGGER trg_secret_usage_observation_immutable BEFORE UPDATE OR DELETE ON secret_usage_observations
 FOR EACH ROW EXECUTE FUNCTION secret_usage_immutable();
CREATE TRIGGER trg_secret_usage_decision_immutable BEFORE UPDATE OR DELETE ON secret_usage_decisions
 FOR EACH ROW EXECUTE FUNCTION secret_usage_immutable();
CREATE TABLE secret_usage_rate_limits (
 account_ref VARCHAR(12) NOT NULL CHECK(account_ref ~ '^[0-9]{12}$'),
 region VARCHAR(40) NOT NULL,
 next_available_at TIMESTAMPTZ NOT NULL,
 PRIMARY KEY(account_ref,region)
);
ALTER TABLE secret_worker_heartbeats DROP CONSTRAINT secret_worker_heartbeats_component_check;
ALTER TABLE secret_worker_heartbeats ADD CONSTRAINT secret_worker_heartbeats_component_check
 CHECK(component IN('SCHEDULER','EXECUTOR','ASSESSMENT','PERMISSIONS','USAGE','MAINTENANCE'));
DO $$ DECLARE prior TEXT; BEGIN
 SELECT pg_get_expr(conbin,conrelid) INTO prior FROM pg_constraint
 WHERE conrelid='secret_audit_events'::regclass AND conname='ck_secret_audit_event_type';
 ALTER TABLE secret_audit_events DROP CONSTRAINT ck_secret_audit_event_type;
 EXECUTE 'ALTER TABLE secret_audit_events ADD CONSTRAINT ck_secret_audit_event_type CHECK(('||prior||') OR event_type IN(''USAGE_REQUESTED'',''USAGE_SUBMITTED'',''USAGE_REVIEWED''))';
END $$;
