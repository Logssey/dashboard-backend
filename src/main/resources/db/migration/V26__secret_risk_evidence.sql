ALTER TABLE secret_exposure_assessments ADD COLUMN exposure_range VARCHAR(10)
 CHECK (exposure_range IN ('BROAD','BOUNDED','UNKNOWN'));
ALTER TABLE secret_exposure_assessments ADD COLUMN access_snapshot JSONB
 CHECK (access_snapshot IS NULL OR jsonb_typeof(access_snapshot)='object');
DO $$ DECLARE prior TEXT; BEGIN
 SELECT pg_get_expr(conbin,conrelid) INTO prior FROM pg_constraint WHERE conrelid='secret_audit_events'::regclass AND conname='ck_secret_audit_event_type';
 ALTER TABLE secret_audit_events DROP CONSTRAINT ck_secret_audit_event_type;
 EXECUTE 'ALTER TABLE secret_audit_events ADD CONSTRAINT ck_secret_audit_event_type CHECK (('||prior||') OR event_type IN (''RISK_EVIDENCE_SUBMITTED'',''RISK_EVIDENCE_DECIDED'',''SEVERITY_ASSESSMENT_REQUESTED'',''SEVERITY_OVERRIDE_PROPOSED'',''SEVERITY_OVERRIDE_REVIEWED''))';
END $$;

CREATE TABLE secret_risk_evidence (
 evidence_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 record_kind VARCHAR(12) NOT NULL CHECK(record_kind IN ('ASSERTION','REVIEW','RETRACTION')),
 kind VARCHAR(30) NOT NULL CHECK(kind IN ('ACCESS_SCOPE','PERMISSION_MAPPING','ASSET_CLASSIFICATION','ABUSE_LINK','ABUSE_COVERAGE')),
 occurrence_id BIGINT NOT NULL REFERENCES secret_occurrences,
 credential_set_id BIGINT NOT NULL REFERENCES secret_credential_sets,
 scope_id BIGINT NOT NULL REFERENCES secret_connection_scopes,
 related_evidence_id BIGINT REFERENCES secret_risk_evidence,
 source_kind VARCHAR(30) NOT NULL CHECK(source_kind IN ('MANUAL','PROVIDER_OBSERVATION','ASSET_REGISTRY')),
 verification_level VARCHAR(30) NOT NULL CHECK(verification_level IN ('MANUAL_SUBMITTED','MANUAL_ACCEPTED','PROVIDER_OBSERVED','ASSET_CLASSIFIED')),
 source_refs JSONB NOT NULL DEFAULT '[]' CHECK(jsonb_typeof(source_refs)='array'),
 safe_payload JSONB NOT NULL CHECK(jsonb_typeof(safe_payload)='object' AND octet_length(safe_payload::text)<=8192),
 limitations JSONB NOT NULL DEFAULT '[]' CHECK(jsonb_typeof(limitations)='array'),
 observed_at TIMESTAMPTZ NOT NULL,
 recorded_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 effective_from TIMESTAMPTZ NOT NULL,
 expires_at TIMESTAMPTZ,
 submitted_by_user_id BIGINT REFERENCES dashboard_users,
 reviewed_by_user_id BIGINT REFERENCES dashboard_users,
 writer_service_id VARCHAR(120),
 review_decision VARCHAR(10) CHECK(review_decision IN ('ACCEPT','REJECT')),
 reason_code VARCHAR(80) NOT NULL,
 evidence_ref VARCHAR(71) NOT NULL CHECK(evidence_ref ~ '^(TICKET|CHANGE|POLICY):[A-Z][A-Z0-9]{0,15}-[1-9][0-9]{0,12}$'),
 safe_payload_digest BYTEA NOT NULL CHECK(octet_length(safe_payload_digest)=32),
 ingestion_key VARCHAR(120) NOT NULL,
 credential_revision BIGINT NOT NULL CHECK(credential_revision>0),
 scope_revision BIGINT NOT NULL CHECK(scope_revision>0),
 source_object_version VARCHAR(200),
 collector_connection_id BIGINT REFERENCES secret_connections,
 collector_identity_ref VARCHAR(120),
 credential_identity_ref VARCHAR(120),
 identity_binding_status VARCHAR(20) CHECK(identity_binding_status IN ('MATCHED','UNRESOLVED','CONFLICT','NOT_APPLICABLE')),
 normalizer_version VARCHAR(80) NOT NULL DEFAULT 'risk-normalizer-v1',
 mapping_version VARCHAR(80),
 asset_classification_version VARCHAR(80),
 CHECK(expires_at IS NULL OR expires_at>effective_from),
 CHECK((record_kind='ASSERTION' AND related_evidence_id IS NULL AND review_decision IS NULL)
 OR(record_kind='REVIEW' AND related_evidence_id IS NOT NULL AND reviewed_by_user_id IS NOT NULL AND review_decision IS NOT NULL AND safe_payload='{}')
 OR(record_kind='RETRACTION' AND related_evidence_id IS NOT NULL AND reviewed_by_user_id IS NOT NULL AND review_decision IS NULL AND safe_payload='{}')),
 CHECK((source_kind='MANUAL' AND submitted_by_user_id IS NOT NULL AND writer_service_id IS NULL AND verification_level IN ('MANUAL_SUBMITTED','MANUAL_ACCEPTED'))
 OR(source_kind<>'MANUAL' AND submitted_by_user_id IS NULL AND writer_service_id IS NOT NULL AND verification_level IN ('PROVIDER_OBSERVED','ASSET_CLASSIFIED'))),
 CHECK(record_kind<>'ASSERTION' OR kind='ABUSE_LINK' OR expires_at IS NOT NULL),
 UNIQUE(scope_id,source_kind,ingestion_key)
);
CREATE INDEX idx_secret_risk_evidence_location ON secret_risk_evidence(occurrence_id,kind,observed_at DESC,evidence_id DESC);
CREATE INDEX idx_secret_risk_evidence_parent ON secret_risk_evidence(related_evidence_id,evidence_id DESC);
CREATE INDEX idx_secret_risk_evidence_expiry ON secret_risk_evidence(expires_at,occurrence_id) WHERE record_kind='ASSERTION' AND expires_at IS NOT NULL;

CREATE FUNCTION secret_risk_evidence_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE o secret_occurrences%ROWTYPE; parent secret_risk_evidence%ROWTYPE;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'RISK_EVIDENCE_IMMUTABLE' USING ERRCODE='23514'; END IF;
 SELECT * INTO o FROM secret_occurrences WHERE occurrence_id=NEW.occurrence_id FOR UPDATE;
 IF o.credential_set_id<>NEW.credential_set_id OR o.scope_id<>NEW.scope_id THEN
  RAISE EXCEPTION 'RISK_EVIDENCE_PARENT_MISMATCH' USING ERRCODE='23514'; END IF;
 IF NEW.related_evidence_id IS NOT NULL THEN
  SELECT * INTO parent FROM secret_risk_evidence WHERE evidence_id=NEW.related_evidence_id;
  IF parent.record_kind<>'ASSERTION' OR parent.occurrence_id<>NEW.occurrence_id OR parent.kind<>NEW.kind THEN
   RAISE EXCEPTION 'RISK_EVIDENCE_REVIEW_PARENT' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER trg_secret_risk_evidence_guard BEFORE INSERT OR UPDATE OR DELETE ON secret_risk_evidence
 FOR EACH ROW EXECUTE FUNCTION secret_risk_evidence_guard();

CREATE FUNCTION secret_risk_bump_evidence() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 UPDATE secret_occurrences SET risk_evidence_revision=risk_evidence_revision+1 WHERE occurrence_id=NEW.occurrence_id;
 RETURN NEW;
END $$;
CREATE TRIGGER trg_secret_risk_evidence_revision AFTER INSERT ON secret_risk_evidence
 FOR EACH ROW EXECUTE FUNCTION secret_risk_bump_evidence();
CREATE TRIGGER trg_secret_exposure_risk_revision AFTER INSERT ON secret_exposure_assessments
 FOR EACH ROW EXECUTE FUNCTION secret_risk_bump_evidence();

CREATE VIEW secret_current_risk_evidence AS
 SELECT e.* FROM secret_risk_evidence e
 WHERE e.record_kind='ASSERTION'
 AND NOT EXISTS(SELECT 1 FROM secret_risk_evidence r WHERE r.related_evidence_id=e.evidence_id AND r.record_kind='RETRACTION')
 AND COALESCE((SELECT r.review_decision='ACCEPT' FROM secret_risk_evidence r
   WHERE r.related_evidence_id=e.evidence_id AND r.record_kind='REVIEW' ORDER BY r.evidence_id DESC LIMIT 1),
   e.verification_level IN ('MANUAL_ACCEPTED','PROVIDER_OBSERVED','ASSET_CLASSIFIED'));
