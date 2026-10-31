-- Permission observations remain review candidates; the existing severity-v2 policy is unchanged.
ALTER TABLE secret_jobs DROP CONSTRAINT ck_secret_job_kind;
ALTER TABLE secret_jobs ADD CONSTRAINT ck_secret_job_kind CHECK(kind IN('FULL_SCAN','REVALIDATE','ASSESS','ENRICH'));
ALTER TABLE secret_jobs DROP CONSTRAINT ck_secret_job_purpose;
ALTER TABLE secret_jobs ADD CONSTRAINT ck_secret_job_purpose CHECK(
 (kind='FULL_SCAN' AND purpose='COLLECTION_AND_DETECTION') OR
 (kind='REVALIDATE' AND purpose IN('LOCATION_RECHECK','CREDENTIAL_VALIDITY')) OR
 (kind='ASSESS' AND purpose='SEVERITY_ASSESSMENT') OR
 (kind='ENRICH' AND purpose='PERMISSION_ASSISTANCE'));
CREATE UNIQUE INDEX uq_secret_permission_active ON secret_jobs(target_occurrence_id)
 WHERE kind='ENRICH' AND status IN('PENDING','LEASED');

CREATE TABLE secret_credential_identities (
 identity_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 validation_attempt_id BIGINT NOT NULL UNIQUE REFERENCES secret_validation_attempts,
 occurrence_id BIGINT NOT NULL REFERENCES secret_occurrences,
 credential_set_id BIGINT NOT NULL REFERENCES secret_credential_sets,
 credential_revision BIGINT NOT NULL,
 scope_revision BIGINT NOT NULL,
 provider VARCHAR(10) NOT NULL CHECK(provider IN('AWS','GITHUB')),
 principal_type VARCHAR(20) NOT NULL CHECK(principal_type IN('IAM_USER','ASSUMED_ROLE','ROOT','GITHUB_USER','UNKNOWN')),
 account_ref VARCHAR(12) CHECK(account_ref ~ '^[0-9]{12}$'),
 principal_ref VARCHAR(512) NOT NULL,
 principal_id VARCHAR(128) NOT NULL,
 safe_claims JSONB NOT NULL DEFAULT '{}' CHECK(jsonb_typeof(safe_claims)='object' AND octet_length(safe_claims::text)<=8192),
 observed_at TIMESTAMPTZ NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL CHECK(expires_at>observed_at),
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 CHECK((provider='AWS' AND account_ref IS NOT NULL AND principal_ref ~ '^arn:aws(-[a-z]+)?:') OR
       (provider='GITHUB' AND account_ref IS NULL AND principal_type='GITHUB_USER' AND principal_ref ~ '^github-user:[1-9][0-9]*$'))
);
CREATE INDEX idx_secret_credential_identity ON secret_credential_identities(occurrence_id,identity_id DESC);
CREATE FUNCTION secret_identity_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'IDENTITY_IMMUTABLE' USING ERRCODE='23514';END IF;
 IF NOT EXISTS(SELECT 1 FROM secret_current_validation_attempts a JOIN secret_occurrences o USING(occurrence_id)
  JOIN secret_credential_sets k ON k.credential_set_id=o.credential_set_id
  WHERE a.attempt_id=NEW.validation_attempt_id AND a.occurrence_id=NEW.occurrence_id
   AND a.credential_set_id=NEW.credential_set_id AND a.credential_revision=NEW.credential_revision
   AND a.scope_revision=NEW.scope_revision AND a.result='VALID' AND a.provider_checked_at IS NOT NULL
   AND k.issuer=NEW.provider) THEN RAISE EXCEPTION 'IDENTITY_VALIDATION_PARENT' USING ERRCODE='23514';END IF;
 RETURN NEW;END $$;
CREATE TRIGGER trg_secret_identity_guard BEFORE INSERT OR UPDATE OR DELETE ON secret_credential_identities
 FOR EACH ROW EXECUTE FUNCTION secret_identity_guard();

CREATE TABLE secret_permission_requests (
 request_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 job_id BIGINT NOT NULL UNIQUE REFERENCES secret_jobs,
 occurrence_id BIGINT NOT NULL REFERENCES secret_occurrences,
 identity_id BIGINT NOT NULL REFERENCES secret_credential_identities,
 collector_connection_id BIGINT NOT NULL REFERENCES secret_connections,
 requested_by_user_id BIGINT NOT NULL REFERENCES dashboard_users,
 context_version VARCHAR(64) NOT NULL CHECK(context_version ~ '^[a-f0-9]{64}$'),
 baseline JSONB NOT NULL CHECK(jsonb_typeof(baseline)='object'),
 requested_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE secret_permission_observations (
 observation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 request_id BIGINT NOT NULL UNIQUE REFERENCES secret_permission_requests,
 status VARCHAR(20) NOT NULL CHECK(status IN('COMPLETE','PARTIAL','UNSUPPORTED')),
 safe_facts JSONB NOT NULL CHECK(jsonb_typeof(safe_facts)='object' AND octet_length(safe_facts::text)<=16384),
 observed_at TIMESTAMPTZ NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL CHECK(expires_at>observed_at),
 observer_version VARCHAR(80) NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE secret_permission_decisions (
 decision_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 observation_id BIGINT NOT NULL UNIQUE REFERENCES secret_permission_observations,
 actor_user_id BIGINT NOT NULL REFERENCES dashboard_users,
 decision VARCHAR(12) NOT NULL CHECK(decision IN('CONFIRMED','REJECTED')),
 evidence_id BIGINT REFERENCES secret_risk_evidence,
 reason_code VARCHAR(80) NOT NULL,
 context_version VARCHAR(64) NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 CHECK((decision='CONFIRMED')=(evidence_id IS NOT NULL))
);
CREATE FUNCTION secret_permission_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'PERMISSION_OBSERVATION_IMMUTABLE' USING ERRCODE='23514';END IF;
 RETURN NEW;END $$;
CREATE TRIGGER trg_secret_permission_requests_immutable BEFORE UPDATE OR DELETE ON secret_permission_requests FOR EACH ROW EXECUTE FUNCTION secret_permission_immutable();
CREATE TRIGGER trg_secret_permission_observations_immutable BEFORE UPDATE OR DELETE ON secret_permission_observations FOR EACH ROW EXECUTE FUNCTION secret_permission_immutable();
CREATE TRIGGER trg_secret_permission_decisions_immutable BEFORE UPDATE OR DELETE ON secret_permission_decisions FOR EACH ROW EXECUTE FUNCTION secret_permission_immutable();
DO $$ DECLARE prior TEXT;BEGIN
 SELECT pg_get_expr(conbin,conrelid) INTO prior FROM pg_constraint WHERE conrelid='secret_audit_events'::regclass AND conname='ck_secret_audit_event_type';
 ALTER TABLE secret_audit_events DROP CONSTRAINT ck_secret_audit_event_type;
 EXECUTE 'ALTER TABLE secret_audit_events ADD CONSTRAINT ck_secret_audit_event_type CHECK(('||prior||') OR event_type IN(''PERMISSION_ASSISTANCE_REQUESTED'',''PERMISSION_ASSISTANCE_CONFIRMED'',''PERMISSION_ASSISTANCE_REJECTED''))';
END $$;
