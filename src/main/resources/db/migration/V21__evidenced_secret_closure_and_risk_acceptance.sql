-- Preserve legacy resolutions without inventing missing verification evidence.
CREATE VIEW secret_current_finding_dispositions AS
 SELECT d.disposition_id,d.decision_id,d.finding_id,d.occurrence_id,d.created_at,d.reuse_expires_at
 FROM secret_finding_dispositions d JOIN secret_occurrences o ON o.occurrence_id=d.occurrence_id
 JOIN secret_connection_scopes scope ON scope.scope_id=o.scope_id
 JOIN secret_credential_sets credential ON credential.credential_set_id=o.credential_set_id
 WHERE d.is_current AND d.revoked_at IS NULL AND d.reuse_expires_at>clock_timestamp()
  AND d.scope_id=scope.scope_id AND d.scope_revision=scope.revision AND d.scope_origin_version=scope.response_origin_version
  AND d.scope_fingerprint=md5(jsonb_build_array(scope.content_type,scope.approved_ref,scope.history_limit)::text)
  AND d.object_version IS NOT DISTINCT FROM o.latest_object_version
  AND d.identity_key_version=credential.fingerprint_key_version
  AND d.protected_evidence_identity=coalesce(credential.fingerprint,credential.candidate_locator)
  AND d.issuer=credential.issuer AND d.credential_type=credential.credential_type
  AND NOT EXISTS(SELECT 1 FROM secret_confirmed_real_credentials real WHERE real.credential_set_id=o.credential_set_id)
  AND (d.reused_from_disposition_id IS NULL OR EXISTS(SELECT 1 FROM secret_finding_dispositions original
    WHERE original.disposition_id=d.reused_from_disposition_id AND original.is_current AND original.revoked_at IS NULL
     AND original.reuse_expires_at>clock_timestamp()));
CREATE TABLE secret_case_resolution_checks (
 check_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 case_id BIGINT NOT NULL REFERENCES secret_response_cases,case_version BIGINT NOT NULL,
 target_origin VARCHAR(20) NOT NULL CHECK(target_origin IN ('PRODUCTION','TEST')),
 version_digest VARCHAR(100) NOT NULL,target_snapshot JSONB NOT NULL,
 check_results JSONB NOT NULL,allowed_coverage_levels JSONB NOT NULL,
 checked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CHECK(jsonb_typeof(target_snapshot)='object' AND jsonb_typeof(check_results)='array' AND jsonb_typeof(allowed_coverage_levels)='array')
);
ALTER TABLE secret_case_resolutions
 ADD COLUMN resolution_id BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
 ADD COLUMN closure_check_id BIGINT REFERENCES secret_case_resolution_checks,
 ADD COLUMN coverage_level VARCHAR(20) CHECK(coverage_level IN ('FULL','LIMITED','SIMULATION')),
 ADD COLUMN evidence_snapshot JSONB,ADD COLUMN limitations JSONB;
ALTER TABLE secret_case_resolution_locations
 ADD COLUMN resolution_id BIGINT REFERENCES secret_case_resolutions(resolution_id),
 ADD COLUMN action_cycle BIGINT,
 ADD COLUMN last_material_action_id BIGINT REFERENCES secret_action_records;

CREATE TABLE secret_exceptions (
 exception_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,case_id BIGINT NOT NULL REFERENCES secret_response_cases,
 reason_code VARCHAR(80) NOT NULL CHECK(reason_code IN ('BUSINESS_CONTINUITY','TEMPORARY_DEPENDENCY','COMPENSATING_CONTROL')),
 evidence_ref VARCHAR(120) NOT NULL CHECK(evidence_ref ~ '^(TICKET|CHANGE|POLICY):[A-Z][A-Z0-9]{0,15}-[1-9][0-9]{0,12}$'),
 approved_by_user_id BIGINT NOT NULL REFERENCES dashboard_users,approved_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 expires_at TIMESTAMPTZ NOT NULL,approved_case_version BIGINT NOT NULL,
 revoked_at TIMESTAMPTZ,revoked_by_user_id BIGINT REFERENCES dashboard_users,revoke_reason_code VARCHAR(80),
 CHECK(expires_at>approved_at AND expires_at<=approved_at+interval '90 days'),
 CHECK((revoked_at IS NULL AND revoked_by_user_id IS NULL AND revoke_reason_code IS NULL)
  OR (revoked_at IS NOT NULL AND revoked_by_user_id IS NOT NULL AND revoke_reason_code IN ('RISK_REDUCED','APPROVAL_WITHDRAWN','SCOPE_CHANGED')))
);
CREATE INDEX idx_secret_active_exception_case ON secret_exceptions(case_id,expires_at) WHERE revoked_at IS NULL;
CREATE TABLE secret_exception_occurrences (
 exception_id BIGINT NOT NULL REFERENCES secret_exceptions,occurrence_id BIGINT NOT NULL REFERENCES secret_occurrences,
 scope_id BIGINT NOT NULL REFERENCES secret_connection_scopes,scope_revision BIGINT NOT NULL,scope_origin_version BIGINT NOT NULL,
 assessment_version BIGINT NOT NULL,PRIMARY KEY(exception_id,occurrence_id)
);
-- The case lock serializes approvals. The guard also prevents direct overlapping active coverage.
CREATE FUNCTION secret_exception_scope_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE target_case BIGINT;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'IMMUTABLE_EXCEPTION_SCOPE'; END IF;
 SELECT case_id INTO STRICT target_case FROM secret_exceptions WHERE exception_id=NEW.exception_id;
 IF NOT EXISTS(SELECT 1 FROM secret_occurrences o JOIN secret_connection_scopes s ON s.scope_id=o.scope_id
    JOIN secret_response_cases c ON c.case_id=target_case
    WHERE o.occurrence_id=NEW.occurrence_id AND o.credential_set_id=c.credential_set_id
     AND (s.response_origin=c.case_origin OR EXISTS(SELECT 1 FROM secret_case_occurrences co WHERE co.case_id=c.case_id AND co.occurrence_id=o.occurrence_id))
     AND NEW.scope_id=s.scope_id AND NEW.scope_revision=s.revision AND NEW.scope_origin_version=s.response_origin_version
     AND NEW.assessment_version=o.exposure_assessment_version)
 THEN RAISE EXCEPTION 'EXCEPTION_SCOPE_MISMATCH'; END IF;
 IF EXISTS(SELECT 1 FROM secret_exception_occurrences prior JOIN secret_exceptions e USING(exception_id)
    WHERE e.case_id=target_case AND prior.occurrence_id=NEW.occurrence_id AND e.revoked_at IS NULL AND e.expires_at>clock_timestamp()
      AND e.exception_id<>NEW.exception_id)
 THEN RAISE EXCEPTION 'ACTIVE_EXCEPTION_OVERLAP'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER secret_exception_scope_guard BEFORE INSERT OR UPDATE OR DELETE ON secret_exception_occurrences
 FOR EACH ROW EXECUTE FUNCTION secret_exception_scope_guard();

CREATE TABLE secret_case_transfer_evidence (
 evidence_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,case_id BIGINT NOT NULL REFERENCES secret_response_cases,
 reason_code VARCHAR(40) NOT NULL CHECK(reason_code IN ('PROGRAM_SCOPE_ENDED','OWNER_TRANSFER')),
 evidence_ref VARCHAR(120) NOT NULL,accepted_transfer_ref VARCHAR(120) NOT NULL,
 submitted_by_user_id BIGINT NOT NULL REFERENCES dashboard_users,submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 case_version BIGINT NOT NULL,
 CHECK(evidence_ref ~ '^(TICKET|CHANGE):[A-Z]{2,10}-[1-9][0-9]{0,9}$'
    AND accepted_transfer_ref ~ '^(TICKET|CHANGE):[A-Z]{2,10}-[1-9][0-9]{0,9}$')
);
CREATE TABLE secret_case_transfer_locations (
 evidence_id BIGINT NOT NULL REFERENCES secret_case_transfer_evidence,occurrence_id BIGINT NOT NULL REFERENCES secret_occurrences,
 scope_id BIGINT NOT NULL REFERENCES secret_connection_scopes,scope_revision BIGINT NOT NULL,scope_origin_version BIGINT NOT NULL,
 assessment_version BIGINT NOT NULL,PRIMARY KEY(evidence_id,occurrence_id)
);
CREATE TABLE secret_case_transfer_reviews (
 review_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,evidence_id BIGINT NOT NULL REFERENCES secret_case_transfer_evidence,
 decision VARCHAR(20) NOT NULL CHECK(decision IN ('APPROVE','REJECT')),
 reason_code VARCHAR(80) NOT NULL CHECK(reason_code IN ('TRANSFER_AND_ACCEPTANCE_CONFIRMED','INSUFFICIENT_EVIDENCE','WRONG_SCOPE')),
 expected_evidence_version BIGINT NOT NULL,case_version BIGINT NOT NULL,
 reviewed_by_user_id BIGINT NOT NULL REFERENCES dashboard_users,reviewed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(evidence_id,expected_evidence_version),CHECK((decision='APPROVE')=(reason_code='TRANSFER_AND_ACCEPTANCE_CONFIRMED'))
);
CREATE TABLE secret_case_dismissals (
 dismissal_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,case_id BIGINT NOT NULL UNIQUE REFERENCES secret_response_cases,
 reason_code VARCHAR(20) NOT NULL CHECK(reason_code IN ('FALSE_POSITIVE','OUT_OF_SCOPE')),
 evidence_snapshot JSONB NOT NULL,accepted_transfer_ref VARCHAR(120),approved_by_user_id BIGINT NOT NULL REFERENCES dashboard_users,
 case_version BIGINT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
-- Closure, transfer and disposition records remain additional evidence rather than editable current flags.
CREATE FUNCTION secret_closure_append_only() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN
 RAISE EXCEPTION 'IMMUTABLE_CLOSURE_EVIDENCE';
END $$;
CREATE TRIGGER secret_resolution_check_immutable BEFORE UPDATE OR DELETE ON secret_case_resolution_checks
 FOR EACH ROW EXECUTE FUNCTION secret_closure_append_only();
CREATE TRIGGER secret_resolution_immutable BEFORE UPDATE OR DELETE ON secret_case_resolutions
 FOR EACH ROW EXECUTE FUNCTION secret_closure_append_only();
CREATE TRIGGER secret_dismissal_immutable BEFORE UPDATE OR DELETE ON secret_case_dismissals
 FOR EACH ROW EXECUTE FUNCTION secret_closure_append_only();
CREATE TRIGGER secret_transfer_evidence_immutable BEFORE UPDATE OR DELETE ON secret_case_transfer_evidence
 FOR EACH ROW EXECUTE FUNCTION secret_closure_append_only();
CREATE TRIGGER secret_transfer_locations_immutable BEFORE UPDATE OR DELETE ON secret_case_transfer_locations
 FOR EACH ROW EXECUTE FUNCTION secret_closure_append_only();
CREATE FUNCTION secret_transfer_review_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE source secret_case_transfer_evidence%ROWTYPE;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'IMMUTABLE_TRANSFER_REVIEW'; END IF;
 SELECT * INTO STRICT source FROM secret_case_transfer_evidence WHERE evidence_id=NEW.evidence_id FOR UPDATE;
 IF source.submitted_by_user_id=NEW.reviewed_by_user_id THEN RAISE EXCEPTION 'INDEPENDENT_TRANSFER_REVIEW_REQUIRED'; END IF;
 IF NEW.expected_evidence_version<>(SELECT 1+count(*) FROM secret_case_transfer_reviews WHERE evidence_id=source.evidence_id)
 THEN RAISE EXCEPTION 'STALE_TRANSFER_REVIEW'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER secret_transfer_review_guard BEFORE INSERT OR UPDATE OR DELETE ON secret_case_transfer_reviews
 FOR EACH ROW EXECUTE FUNCTION secret_transfer_review_guard();

DO $$ DECLARE old_expression TEXT; BEGIN
 SELECT pg_get_expr(conbin,conrelid) INTO old_expression FROM pg_constraint WHERE conrelid='secret_audit_events'::regclass AND conname='ck_secret_audit_event_type';
 EXECUTE 'ALTER TABLE secret_audit_events DROP CONSTRAINT ck_secret_audit_event_type';
 EXECUTE 'ALTER TABLE secret_audit_events ADD CONSTRAINT ck_secret_audit_event_type CHECK (('||old_expression||') OR event_type IN (
  ''CASE_RESOLUTION_CONFIRMED'',''CASE_DISMISSED'',''RISK_EXCEPTION_APPROVED'',''RISK_EXCEPTION_REVOKED'',''TRANSFER_EVIDENCE_SUBMITTED'',''TRANSFER_EVIDENCE_REVIEWED''))';
 SELECT pg_get_expr(conbin,conrelid) INTO old_expression FROM pg_constraint WHERE conrelid='secret_location_activities'::regclass AND conname='secret_location_activities_activity_type_check';
 EXECUTE 'ALTER TABLE secret_location_activities DROP CONSTRAINT secret_location_activities_activity_type_check';
 EXECUTE 'ALTER TABLE secret_location_activities ADD CONSTRAINT secret_location_activities_activity_type_check CHECK (('||old_expression||') OR activity_type IN (
  ''CASE_RESOLVED'',''CASE_DISMISSED'',''EXCEPTION_APPROVED'',''EXCEPTION_REVOKED'',''TRANSFER_SUBMITTED'',''TRANSFER_REVIEWED''))';
END $$;
