-- Shared credential verification. No raw credential, provider body or header is stored.
ALTER TABLE secret_credential_sets ADD COLUMN credential_revision BIGINT NOT NULL DEFAULT 1 CHECK (credential_revision>0);
ALTER TABLE secret_occurrences ADD COLUMN risk_evidence_revision BIGINT NOT NULL DEFAULT 0 CHECK (risk_evidence_revision>=0);
ALTER TABLE secret_connections
 ADD COLUMN validation_enabled BOOLEAN NOT NULL DEFAULT false,
 ADD COLUMN validation_profile_version VARCHAR(80),
 ADD COLUMN validation_revision BIGINT NOT NULL DEFAULT 1 CHECK(validation_revision>0),
 ADD CONSTRAINT ck_secret_validation_connection_profile CHECK(NOT validation_enabled OR validation_profile_version IS NOT NULL);
ALTER TABLE secret_connection_scopes
 ADD COLUMN validation_approved BOOLEAN NOT NULL DEFAULT false,
 ADD COLUMN validation_approval_revision BIGINT NOT NULL DEFAULT 1 CHECK(validation_approval_revision>0),
 ADD COLUMN validation_profile_version VARCHAR(80),
 ADD COLUMN validation_approved_by_user_id BIGINT REFERENCES dashboard_users(user_id),
 ADD COLUMN validation_approved_at TIMESTAMPTZ,
 ADD COLUMN synthetic_fixture BOOLEAN NOT NULL DEFAULT false,
 ADD CONSTRAINT ck_secret_validation_scope_profile CHECK(NOT validation_approved OR
  (validation_profile_version IS NOT NULL AND validation_approved_by_user_id IS NOT NULL AND validation_approved_at IS NOT NULL));
-- Existing explicitly synthetic experiment source remains guarded independently of TEST labels.
UPDATE secret_connection_scopes SET synthetic_fixture=true
 WHERE approved_ref ~* '^https://github[.]com/Logssey/test-find-key(/|$)';
ALTER TABLE secret_jobs DROP CONSTRAINT ck_secret_job_kind;
ALTER TABLE secret_jobs ADD CONSTRAINT ck_secret_job_kind CHECK(kind IN('FULL_SCAN','REVALIDATE','ASSESS'));
ALTER TABLE secret_jobs
 ADD COLUMN purpose VARCHAR(40),
 ADD COLUMN target_occurrence_id BIGINT REFERENCES secret_occurrences(occurrence_id),
 ADD COLUMN expected_context JSONB,
 ADD COLUMN expected_evidence_revision BIGINT,
 ADD COLUMN lease_token UUID,
 ADD COLUMN lease_generation BIGINT NOT NULL DEFAULT 0 CHECK(lease_generation>=0);
UPDATE secret_jobs SET purpose=CASE kind WHEN 'FULL_SCAN' THEN 'COLLECTION_AND_DETECTION' ELSE 'LOCATION_RECHECK' END;
ALTER TABLE secret_jobs ALTER COLUMN purpose SET NOT NULL;
ALTER TABLE secret_jobs ADD CONSTRAINT ck_secret_job_purpose CHECK(
 (kind='FULL_SCAN' AND purpose='COLLECTION_AND_DETECTION') OR
 (kind='REVALIDATE' AND purpose IN('LOCATION_RECHECK','CREDENTIAL_VALIDITY')) OR
 (kind='ASSESS' AND purpose='SEVERITY_ASSESSMENT'));
ALTER TABLE secret_jobs ADD CONSTRAINT ck_secret_job_context CHECK(expected_context IS NULL OR jsonb_typeof(expected_context)='object');
DROP INDEX uq_secret_job_active_connection;
CREATE UNIQUE INDEX uq_secret_job_active_connection ON secret_jobs(connection_id)
 WHERE kind IN('FULL_SCAN','REVALIDATE') AND status IN('PENDING','LEASED');
-- Older code uses lease_owner as the fencing token. Preserve it while introducing typed tokens.
UPDATE secret_jobs SET lease_token=md5(lease_owner)::uuid,lease_generation=1 WHERE status='LEASED';

ALTER TABLE secret_validation_attempts
 ALTER COLUMN result DROP NOT NULL, ALTER COLUMN reason_code DROP NOT NULL, ALTER COLUMN completed_at DROP NOT NULL,
 DROP CONSTRAINT ck_secret_validation_timestamps, DROP CONSTRAINT ck_secret_validation_checked,
 ADD COLUMN evidence_version SMALLINT NOT NULL DEFAULT 0,
 ADD COLUMN attempt_state VARCHAR(20) NOT NULL DEFAULT 'COMPLETED',
 ADD COLUMN request_sent_at TIMESTAMPTZ,
 ADD COLUMN scope_id BIGINT REFERENCES secret_connection_scopes(scope_id),
 ADD COLUMN occurrence_id BIGINT REFERENCES secret_occurrences(occurrence_id),
 ADD COLUMN source_finding_id BIGINT REFERENCES secret_findings(finding_id),
 ADD COLUMN source_object_version_digest BYTEA CHECK(source_object_version_digest IS NULL OR octet_length(source_object_version_digest)=32),
 ADD COLUMN credential_revision BIGINT,
 ADD COLUMN scope_revision BIGINT,
 ADD COLUMN validation_revision BIGINT,
 ADD COLUMN validation_approval_revision BIGINT,
 ADD COLUMN validation_profile_version VARCHAR(80),
 ADD COLUMN action_context_digest BYTEA,
 ADD COLUMN dedup_key BYTEA,
 ADD COLUMN cycle_key VARCHAR(120),
 ADD COLUMN attempt_no INTEGER,
 ADD COLUMN reservation_generation BIGINT,
 ADD COLUMN reservation_token UUID,
 ADD COLUMN current_eligible BOOLEAN NOT NULL DEFAULT false,
 ADD COLUMN ineligible_reason_code VARCHAR(80),
 ADD COLUMN http_status INTEGER CHECK(http_status BETWEEN 100 AND 599);
UPDATE secret_validation_attempts SET ineligible_reason_code='LEGACY_UNAVAILABLE';
-- Compatibility writers lacking the new evidence fields remain explicit, ineligible legacy history.
ALTER TABLE secret_validation_attempts ALTER COLUMN ineligible_reason_code SET DEFAULT 'LEGACY_UNAVAILABLE';
ALTER TABLE secret_validation_attempts ADD CONSTRAINT ck_secret_validation_lifecycle CHECK(
 (evidence_version=0 AND attempt_state='COMPLETED' AND result IS NOT NULL AND completed_at IS NOT NULL AND NOT current_eligible)
 OR (evidence_version=1 AND (
  (attempt_state='RESERVED' AND result IS NULL AND reason_code IS NULL AND completed_at IS NULL AND request_sent_at IS NULL AND provider_checked_at IS NULL) OR
  (attempt_state='SENT' AND result IS NULL AND reason_code IS NULL AND completed_at IS NULL AND request_sent_at IS NOT NULL AND provider_checked_at IS NULL) OR
  (attempt_state='COMPLETED' AND result IS NOT NULL AND reason_code IS NOT NULL AND completed_at IS NOT NULL
   AND (result NOT IN('VALID','INVALID') OR (request_sent_at IS NOT NULL AND provider_checked_at IS NOT NULL))
   AND (result<>'UNCHECKED' OR (request_sent_at IS NULL AND provider_checked_at IS NULL))) OR
  (attempt_state='ABANDONED' AND result IS NULL AND reason_code IS NOT NULL AND completed_at IS NOT NULL))));
ALTER TABLE secret_validation_attempts ADD CONSTRAINT ck_secret_validation_evidence CHECK(evidence_version=0 OR
 (scope_id IS NOT NULL AND occurrence_id IS NOT NULL AND credential_revision IS NOT NULL AND scope_revision IS NOT NULL AND validation_revision IS NOT NULL
 AND validation_approval_revision IS NOT NULL AND action_context_digest IS NOT NULL AND dedup_key IS NOT NULL AND attempt_no IS NOT NULL AND reservation_generation IS NOT NULL
 AND credential_revision>0 AND scope_revision>0 AND validation_revision>0
 AND validation_approval_revision>0 AND octet_length(action_context_digest)=32 AND octet_length(dedup_key)=32
 AND cycle_key IS NOT NULL AND attempt_no>0 AND reservation_generation>0 AND reservation_token IS NOT NULL
 AND (validation_profile_version IS NOT NULL OR (attempt_state='COMPLETED' AND result='UNCHECKED' AND request_sent_at IS NULL AND provider_checked_at IS NULL))
 AND (result NOT IN('VALID','INVALID') OR source_finding_id IS NOT NULL)));
ALTER TABLE secret_validation_attempts ADD CONSTRAINT ck_secret_validation_times CHECK(
 (completed_at IS NULL OR completed_at>=requested_at) AND
 (request_sent_at IS NULL OR (request_sent_at>=requested_at AND (completed_at IS NULL OR request_sent_at<=completed_at))) AND
 (provider_checked_at IS NULL OR (provider_checked_at>=requested_at AND provider_checked_at<=completed_at
  AND (evidence_version=0 OR (request_sent_at IS NOT NULL AND provider_checked_at>=request_sent_at)))));
ALTER TABLE secret_validation_attempts ADD CONSTRAINT ck_secret_validation_eligible CHECK(
 NOT current_eligible OR (attempt_state='COMPLETED' AND evidence_version=1));
ALTER TABLE secret_validation_attempts ADD CONSTRAINT ck_secret_validation_ineligible CHECK(
 attempt_state<>'COMPLETED' OR current_eligible OR ineligible_reason_code IS NOT NULL);
CREATE UNIQUE INDEX uq_secret_validation_reservation ON secret_validation_attempts(credential_set_id,validator_id,validator_version,dedup_key)
 WHERE attempt_state IN('RESERVED','SENT');
CREATE INDEX idx_secret_validation_completed ON secret_validation_attempts(credential_set_id,completed_at DESC,attempt_id DESC)
 WHERE attempt_state='COMPLETED';
CREATE INDEX idx_secret_validation_job_state ON secret_validation_attempts(job_id,attempt_state);
CREATE INDEX idx_secret_validation_rate ON secret_validation_attempts(endpoint_class,request_sent_at) WHERE request_sent_at IS NOT NULL;

CREATE VIEW secret_validation_context AS
 SELECT o.occurrence_id,o.credential_set_id,o.connection_id,o.scope_id,
  k.issuer,k.credential_type,k.component_state,k.credential_revision,k.fingerprint_key_version,c.provider AS source_provider,
  o.exposure_assessment_version AS occurrence_revision,s.revision AS scope_revision,
  s.validation_approval_revision,c.validation_revision,c.scope_version,c.status AS connection_status,
  s.enabled AS scope_enabled,c.validation_enabled,s.validation_approved,
  (s.synthetic_fixture OR s.approved_ref ~* '^github://Logssey/test-find-key/' OR EXISTS(SELECT 1 FROM secret_current_fixture_attestations fa WHERE fa.credential_set_id=k.credential_set_id AND fa.scope_id=s.scope_id)) AS synthetic_fixture,
  c.validation_profile_version AS connection_profile,s.validation_profile_version AS scope_profile,
  COALESCE(a.action_id,0) AS action_id,a.performed_at AS action_performed_at,
  encode(sha256(convert_to(concat_ws(':',o.occurrence_id,k.credential_set_id,k.credential_revision,k.fingerprint_key_version,
   o.exposure_assessment_version,s.revision,s.validation_approval_revision,c.validation_revision,c.scope_version,
   c.status,s.enabled,c.validation_enabled,s.validation_approved,c.validation_profile_version,s.validation_profile_version,
   s.synthetic_fixture,COALESCE(a.action_id,0),a.performed_at),'UTF8')),'hex') AS context_version
 FROM secret_occurrences o JOIN secret_credential_sets k USING(credential_set_id)
 JOIN secret_connection_scopes s ON s.scope_id=o.scope_id JOIN secret_connections c ON c.connection_id=o.connection_id
 LEFT JOIN LATERAL(SELECT action_id,performed_at FROM secret_action_records WHERE occurrence_id=o.occurrence_id ORDER BY performed_at DESC,action_id DESC LIMIT 1) a ON true;

CREATE VIEW secret_current_validation_attempts AS
 SELECT a.* FROM secret_validation_attempts a JOIN secret_validation_context v ON v.occurrence_id=a.occurrence_id
 WHERE a.evidence_version=1 AND a.attempt_state='COMPLETED' AND a.current_eligible
 AND a.credential_set_id=v.credential_set_id AND a.credential_revision=v.credential_revision AND a.scope_id=v.scope_id
 AND a.scope_revision=v.scope_revision AND a.validation_revision=v.validation_revision AND a.validation_approval_revision=v.validation_approval_revision
 AND (a.result='UNCHECKED' OR (v.connection_status='ACTIVE' AND v.scope_enabled AND v.validation_enabled AND v.validation_approved
  AND a.validation_profile_version=v.connection_profile AND v.connection_profile=v.scope_profile AND NOT v.synthetic_fixture));

CREATE FUNCTION secret_validation_job_defaults() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF NEW.purpose IS NULL THEN NEW.purpose:=CASE NEW.kind WHEN 'FULL_SCAN' THEN 'COLLECTION_AND_DETECTION' WHEN 'REVALIDATE' THEN 'LOCATION_RECHECK' WHEN 'ASSESS' THEN 'SEVERITY_ASSESSMENT' END; END IF;
 RETURN NEW; END $$;
CREATE TRIGGER secret_validation_job_defaults BEFORE INSERT ON secret_jobs FOR EACH ROW EXECUTE FUNCTION secret_validation_job_defaults();
CREATE FUNCTION secret_validation_credential_revision() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF (OLD.component_state,OLD.fingerprint,OLD.candidate_locator,OLD.fingerprint_key_version,OLD.issuer,OLD.credential_type)
 IS DISTINCT FROM (NEW.component_state,NEW.fingerprint,NEW.candidate_locator,NEW.fingerprint_key_version,NEW.issuer,NEW.credential_type)
 THEN NEW.credential_revision:=GREATEST(OLD.credential_revision+1,NEW.credential_revision); END IF;
 RETURN NEW; END $$;
CREATE TRIGGER secret_validation_credential_revision BEFORE UPDATE ON secret_credential_sets FOR EACH ROW EXECUTE FUNCTION secret_validation_credential_revision();

DO $$ DECLARE prior TEXT; BEGIN
 SELECT pg_get_expr(conbin,conrelid) INTO prior FROM pg_constraint WHERE conrelid='secret_audit_events'::regclass AND conname='ck_secret_audit_event_type';
 ALTER TABLE secret_audit_events DROP CONSTRAINT ck_secret_audit_event_type;
 EXECUTE 'ALTER TABLE secret_audit_events ADD CONSTRAINT ck_secret_audit_event_type CHECK (('||prior||') OR event_type IN (''CREDENTIAL_VALIDATION_REQUESTED'',''VALIDATION_POLICY_CHANGED'',''VALIDATION_PROFILE_CHANGED''))';
END $$;
