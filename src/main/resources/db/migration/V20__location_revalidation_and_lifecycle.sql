-- Historical revalidations keep NULL comparison snapshots and cannot prove current absence.
ALTER TABLE secret_case_revalidations
 ADD COLUMN scope_revision BIGINT,
 ADD COLUMN scope_origin_version BIGINT,
 ADD COLUMN baseline_identity BYTEA,
 ADD COLUMN action_cycle BIGINT,
 ADD COLUMN occurrence_version BIGINT,
 ADD COLUMN last_material_action_at TIMESTAMPTZ,
 ADD COLUMN actions_completed_at TIMESTAMPTZ;
CREATE TABLE secret_credential_lifecycle_evidence (
 evidence_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 case_id BIGINT NOT NULL REFERENCES secret_response_cases,
 credential_set_id BIGINT NOT NULL REFERENCES secret_credential_sets,
 source_occurrence_id BIGINT NOT NULL REFERENCES secret_occurrences,
 origin VARCHAR(20) NOT NULL CHECK(origin IN ('PRODUCTION','TEST')),
 kind VARCHAR(30) NOT NULL CHECK(kind IN ('ROTATED','REVOKED','RETIRED','FIXTURE_RETIRED')),
 verification_method VARCHAR(30) NOT NULL CHECK(verification_method IN ('EXTERNAL_RECORD','PROVIDER')),
 verification_level VARCHAR(30) NOT NULL CHECK(verification_level IN ('PENDING','PROVIDER_VERIFIED')),
 evidence_ref VARCHAR(120), provider_validator_id VARCHAR(120), validator_version VARCHAR(80), endpoint_class VARCHAR(80), reason_code VARCHAR(80),
 performed_at TIMESTAMPTZ NOT NULL, observed_at TIMESTAMPTZ NOT NULL,
 submitted_by_user_id BIGINT REFERENCES dashboard_users,
 version BIGINT NOT NULL DEFAULT 1 CHECK(version=1), created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 CHECK ((verification_method='EXTERNAL_RECORD' AND verification_level='PENDING' AND submitted_by_user_id IS NOT NULL
       AND evidence_ref ~ '^(TICKET|CHANGE):[A-Z]{2,10}-[1-9][0-9]{0,9}$'
       AND provider_validator_id IS NULL AND validator_version IS NULL AND endpoint_class IS NULL AND reason_code IS NULL)
   OR (verification_method='PROVIDER' AND verification_level='PROVIDER_VERIFIED' AND kind<>'FIXTURE_RETIRED'
       AND submitted_by_user_id IS NULL AND evidence_ref IS NULL AND provider_validator_id IS NOT NULL
       AND validator_version IS NOT NULL AND endpoint_class IS NOT NULL AND reason_code='CONFIRMED_KEY_RETIRED')),
 CHECK(kind<>'FIXTURE_RETIRED' OR origin='TEST'), CHECK(observed_at>=performed_at)
);
-- Deployment operators grant this exclusively to a separate trusted observation writer.
-- No currently deployed STS validator can assert retirement: its INVALID/denied result is insufficient.
CREATE TABLE secret_lifecycle_provider_writers (database_role NAME PRIMARY KEY);
REVOKE ALL ON secret_lifecycle_provider_writers FROM PUBLIC;
CREATE TABLE secret_lifecycle_provider_capabilities (
 provider_validator_id VARCHAR(120) NOT NULL,validator_version VARCHAR(80) NOT NULL,endpoint_class VARCHAR(80) NOT NULL,
 kind VARCHAR(30) NOT NULL CHECK(kind IN ('ROTATED','REVOKED','RETIRED')),
 PRIMARY KEY(provider_validator_id,validator_version,endpoint_class,kind)
);
REVOKE ALL ON secret_lifecycle_provider_capabilities FROM PUBLIC;
CREATE FUNCTION secret_lifecycle_evidence_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'IMMUTABLE_LIFECYCLE_EVIDENCE'; END IF;
 IF NOT EXISTS(SELECT 1 FROM secret_response_cases c JOIN secret_case_occurrences co USING(case_id)
   JOIN secret_occurrences o USING(occurrence_id) WHERE c.case_id=NEW.case_id AND c.credential_set_id=NEW.credential_set_id
   AND c.case_origin=NEW.origin AND o.credential_set_id=NEW.credential_set_id AND o.occurrence_id=NEW.source_occurrence_id)
 THEN RAISE EXCEPTION 'LIFECYCLE_TARGET_MISMATCH'; END IF;
 IF NEW.verification_method='PROVIDER' AND NOT EXISTS(SELECT 1 FROM secret_lifecycle_provider_writers w WHERE w.database_role=current_user)
 THEN RAISE EXCEPTION 'TRUSTED_LIFECYCLE_WRITER_REQUIRED'; END IF;
 IF NEW.verification_method='PROVIDER' AND NOT EXISTS(SELECT 1 FROM secret_lifecycle_provider_capabilities cap
   WHERE cap.provider_validator_id=NEW.provider_validator_id AND cap.validator_version=NEW.validator_version
     AND cap.endpoint_class=NEW.endpoint_class AND cap.kind=NEW.kind)
 THEN RAISE EXCEPTION 'UNAPPROVED_LIFECYCLE_VALIDATOR'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER secret_lifecycle_evidence_guard BEFORE INSERT OR UPDATE OR DELETE ON secret_credential_lifecycle_evidence
 FOR EACH ROW EXECUTE FUNCTION secret_lifecycle_evidence_guard();
CREATE TABLE secret_lifecycle_evidence_reviews (
 review_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, evidence_id BIGINT NOT NULL REFERENCES secret_credential_lifecycle_evidence,
 decision VARCHAR(20) NOT NULL CHECK(decision IN ('APPROVE','REJECT')),
 reason_code VARCHAR(80) NOT NULL CHECK(reason_code IN ('EXTERNAL_RECORD_CONFIRMED','INSUFFICIENT_EVIDENCE','WRONG_CREDENTIAL','CONTRADICTORY_EVIDENCE')),
 expected_evidence_version BIGINT NOT NULL, case_version BIGINT NOT NULL,
 reviewed_by_user_id BIGINT NOT NULL REFERENCES dashboard_users,
 limitations JSONB NOT NULL DEFAULT '["PROVIDER_RETIREMENT_NOT_VERIFIED"]', reviewed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
 UNIQUE(evidence_id,expected_evidence_version), CHECK((decision='APPROVE')=(reason_code='EXTERNAL_RECORD_CONFIRMED'))
);
CREATE FUNCTION secret_lifecycle_review_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE e secret_credential_lifecycle_evidence%ROWTYPE;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'IMMUTABLE_LIFECYCLE_REVIEW'; END IF;
 SELECT * INTO STRICT e FROM secret_credential_lifecycle_evidence WHERE evidence_id=NEW.evidence_id FOR UPDATE;
 IF e.verification_method<>'EXTERNAL_RECORD' OR e.submitted_by_user_id=NEW.reviewed_by_user_id
 THEN RAISE EXCEPTION 'INDEPENDENT_LIFECYCLE_REVIEW_REQUIRED'; END IF;
 IF NEW.expected_evidence_version<>(SELECT 1+count(*) FROM secret_lifecycle_evidence_reviews WHERE evidence_id=e.evidence_id)
 THEN RAISE EXCEPTION 'STALE_LIFECYCLE_REVIEW'; END IF;
 IF NOT EXISTS(SELECT 1 FROM secret_case_occurrences WHERE case_id=e.case_id) OR EXISTS(
 SELECT 1 FROM secret_case_occurrences co JOIN secret_occurrences o USING(occurrence_id)
 WHERE co.case_id=e.case_id AND NOT EXISTS(SELECT 1 FROM secret_role_grants g WHERE g.user_id=NEW.reviewed_by_user_id
 AND g.role='SECURITY' AND g.revoked_at IS NULL AND (g.connection_id IS NULL OR g.connection_id=o.connection_id)))
 THEN RAISE EXCEPTION 'LIFECYCLE_REVIEW_PERMISSION_REQUIRED'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER secret_lifecycle_review_guard BEFORE INSERT OR UPDATE OR DELETE ON secret_lifecycle_evidence_reviews
 FOR EACH ROW EXECUTE FUNCTION secret_lifecycle_review_guard();
CREATE TABLE secret_lifecycle_evidence_applications (
 application_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY, evidence_id BIGINT NOT NULL REFERENCES secret_credential_lifecycle_evidence,
 case_id BIGINT NOT NULL REFERENCES secret_response_cases, credential_set_id BIGINT NOT NULL REFERENCES secret_credential_sets,
 origin VARCHAR(20) NOT NULL CHECK(origin IN ('PRODUCTION','TEST')), reviewed_by_user_id BIGINT NOT NULL REFERENCES dashboard_users,
 reviewed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(evidence_id,case_id)
);
CREATE VIEW secret_current_lifecycle_evidence AS
 SELECT e.evidence_id,e.case_id,e.credential_set_id,e.source_occurrence_id,e.origin,e.kind,e.performed_at,e.observed_at,
 CASE WHEN e.verification_level='PROVIDER_VERIFIED' THEN 'PROVIDER_VERIFIED' ELSE 'APPROVED_MANUAL' END::varchar AS verification_level,
 1+COALESCE(r.review_count,0) AS version
 FROM secret_credential_lifecycle_evidence e
 LEFT JOIN LATERAL(SELECT count(*) AS review_count FROM secret_lifecycle_evidence_reviews WHERE evidence_id=e.evidence_id)r ON true
 LEFT JOIN LATERAL(SELECT decision FROM secret_lifecycle_evidence_reviews WHERE evidence_id=e.evidence_id ORDER BY review_id DESC LIMIT 1)last ON true
 WHERE (e.verification_level='PROVIDER_VERIFIED' OR last.decision='APPROVE')
 AND NOT EXISTS(SELECT 1 FROM secret_validation_attempts v WHERE v.credential_set_id=e.credential_set_id
    AND v.result='VALID' AND v.reason_code='AUTHENTICATED' AND v.provider_checked_at>e.performed_at)
 AND (e.kind<>'FIXTURE_RETIRED' OR (NOT EXISTS(SELECT 1 FROM secret_confirmed_real_credentials real WHERE real.credential_set_id=e.credential_set_id)
   AND NOT EXISTS(SELECT 1 FROM secret_case_occurrences co JOIN secret_occurrences o USING(occurrence_id) WHERE co.case_id=e.case_id
    AND NOT EXISTS(SELECT 1 FROM secret_current_fixture_attestations a WHERE a.credential_set_id=e.credential_set_id AND a.scope_id=o.scope_id))));
ALTER TABLE secret_location_activities DROP CONSTRAINT secret_location_activities_activity_type_check;
ALTER TABLE secret_location_activities ADD CONSTRAINT secret_location_activities_activity_type_check CHECK(activity_type IN
 ('LOCATION_ASSIGNED','ACTION_RECORDED','ACTIONS_COMPLETED','CHECKLIST_CHANGED','COORDINATOR_ASSIGNED','REVALIDATION_REQUESTED','REVALIDATION_RESUMED','LIFECYCLE_SUBMITTED','LIFECYCLE_REVIEWED'));
ALTER TABLE secret_audit_events ALTER COLUMN event_type TYPE VARCHAR(80);
DO $$ DECLARE old_expression TEXT; BEGIN
 SELECT pg_get_expr(conbin,conrelid) INTO old_expression FROM pg_constraint WHERE conrelid='secret_audit_events'::regclass AND conname='ck_secret_audit_event_type';
 EXECUTE 'ALTER TABLE secret_audit_events DROP CONSTRAINT ck_secret_audit_event_type';
 EXECUTE 'ALTER TABLE secret_audit_events ADD CONSTRAINT ck_secret_audit_event_type CHECK (('||old_expression||') OR event_type IN (''LOCATION_REVALIDATION_REQUESTED'',''LOCATION_REVALIDATION_RESUMED'',''LIFECYCLE_EVIDENCE_SUBMITTED'',''LIFECYCLE_EVIDENCE_REVIEWED''))';
END $$;

CREATE FUNCTION secret_lifecycle_application_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE e secret_current_lifecycle_evidence%ROWTYPE;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'IMMUTABLE_LIFECYCLE_APPLICATION'; END IF;
 SELECT * INTO STRICT e FROM secret_current_lifecycle_evidence WHERE evidence_id=NEW.evidence_id;
 IF NOT EXISTS(SELECT 1 FROM secret_response_cases c WHERE c.case_id=NEW.case_id AND c.is_current
   AND c.credential_set_id=e.credential_set_id AND NEW.credential_set_id=e.credential_set_id AND c.case_origin=NEW.origin)
 OR NOT EXISTS(SELECT 1 FROM secret_case_occurrences WHERE case_id=NEW.case_id)
 OR EXISTS(SELECT 1 FROM secret_case_occurrences co JOIN secret_occurrences o USING(occurrence_id)
   WHERE co.case_id IN (NEW.case_id,e.case_id) AND NOT EXISTS(SELECT 1 FROM secret_role_grants g
    WHERE g.user_id=NEW.reviewed_by_user_id AND g.role='SECURITY' AND g.revoked_at IS NULL
    AND (g.connection_id IS NULL OR g.connection_id=o.connection_id)))
 THEN RAISE EXCEPTION 'LIFECYCLE_APPLICATION_MISMATCH'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER secret_lifecycle_application_guard BEFORE INSERT OR UPDATE OR DELETE ON secret_lifecycle_evidence_applications
 FOR EACH ROW EXECUTE FUNCTION secret_lifecycle_application_guard();
-- A closed, evidenced retirement is not reopened merely because an old disabled value remains in a source.
-- A later real authentication invalidates current lifecycle evidence and re-enables the normal warning rule.
DO $$ DECLARE definition TEXT; needle TEXT:='  PERFORM 1 FROM secret_credential_sets WHERE credential_set_id=k.credential_set_id FOR UPDATE;'; BEGIN
 SELECT pg_get_functiondef('secret_reconcile_test_alerts(bigint)'::regprocedure) INTO definition;
 IF position(needle IN definition)=0 THEN RAISE EXCEPTION 'ALERT_RECONCILIATION_HOOK_MISSING'; END IF;
 definition:=replace(definition,needle,needle||'
  IF EXISTS(SELECT 1 FROM secret_cross_environment_alerts old
    JOIN secret_current_lifecycle_evidence e ON e.credential_set_id=old.credential_set_id
    WHERE old.credential_set_id=k.credential_set_id AND old.status=''CLOSED''
     AND old.closure_evidence_snapshot->>''reasonCode''=''CREDENTIAL_RETIRED''
     AND e.kind IN (''ROTATED'',''REVOKED'',''RETIRED'')) THEN CONTINUE; END IF;');
 EXECUTE definition;
END $$;
