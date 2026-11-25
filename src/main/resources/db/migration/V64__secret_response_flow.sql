-- Reuse recorded external actions and retain the level of manual self-attestation.
ALTER TABLE secret_credential_lifecycle_evidence
 ADD COLUMN source_action_id BIGINT REFERENCES secret_action_records(action_id),
 ADD COLUMN source_action_recorded_by_user_id BIGINT REFERENCES dashboard_users(user_id),
 ADD CONSTRAINT ck_secret_lifecycle_source_action_author CHECK(
  (source_action_id IS NULL)=(source_action_recorded_by_user_id IS NULL));
CREATE UNIQUE INDEX uq_secret_lifecycle_source_action
 ON secret_credential_lifecycle_evidence(case_id,source_action_id) WHERE source_action_id IS NOT NULL;

ALTER TABLE secret_lifecycle_evidence_reviews
 DROP CONSTRAINT secret_lifecycle_evidence_reviews_reason_code_check,
 DROP CONSTRAINT secret_lifecycle_evidence_reviews_check;
ALTER TABLE secret_lifecycle_evidence_reviews
 ADD CONSTRAINT ck_secret_lifecycle_review_reason CHECK(reason_code IN
 ('EXTERNAL_RECORD_CONFIRMED','SELF_ATTESTATION_LIMITED','INSUFFICIENT_EVIDENCE','WRONG_CREDENTIAL','CONTRADICTORY_EVIDENCE')),
 ADD CONSTRAINT ck_secret_lifecycle_review_decision CHECK((decision='APPROVE')=
 (reason_code IN ('EXTERNAL_RECORD_CONFIRMED','SELF_ATTESTATION_LIMITED')));

CREATE OR REPLACE FUNCTION secret_lifecycle_review_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE e secret_credential_lifecycle_evidence%ROWTYPE;
DECLARE qualified_reviewers BIGINT;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'IMMUTABLE_LIFECYCLE_REVIEW'; END IF;
 SELECT * INTO STRICT e FROM secret_credential_lifecycle_evidence WHERE evidence_id=NEW.evidence_id FOR UPDATE;
 IF e.verification_method<>'EXTERNAL_RECORD' THEN RAISE EXCEPTION 'INDEPENDENT_LIFECYCLE_REVIEW_REQUIRED'; END IF;
 IF NEW.reason_code='SELF_ATTESTATION_LIMITED' THEN
  IF NEW.decision<>'APPROVE' OR e.submitted_by_user_id<>NEW.reviewed_by_user_id
  THEN RAISE EXCEPTION 'SELF_ATTESTATION_SUBMITTER_REQUIRED'; END IF;
  IF EXISTS(SELECT 1 FROM secret_lifecycle_evidence_reviews WHERE evidence_id=e.evidence_id)
  THEN RAISE EXCEPTION 'SELF_ATTESTATION_REQUIRES_UNREVIEWED_EVIDENCE'; END IF;
  LOCK TABLE secret_role_grants IN SHARE MODE;
  SELECT count(*) INTO qualified_reviewers FROM (
   SELECT DISTINCT user_id FROM secret_role_grants WHERE role='SECURITY' AND revoked_at IS NULL
  ) reviewers WHERE NOT EXISTS(
   SELECT 1 FROM secret_case_occurrences co JOIN secret_occurrences o USING(occurrence_id)
   WHERE co.case_id=e.case_id AND NOT EXISTS(
    SELECT 1 FROM secret_role_grants g WHERE g.user_id=reviewers.user_id AND g.role='SECURITY'
     AND g.revoked_at IS NULL AND (g.connection_id IS NULL OR g.connection_id=o.connection_id)));
  IF qualified_reviewers<>1 THEN RAISE EXCEPTION 'SINGLE_REVIEWER_POLICY_REQUIRED'; END IF;
  NEW.limitations='["SELF_ATTESTED","PROVIDER_RETIREMENT_NOT_VERIFIED"]'::jsonb;
 ELSIF e.submitted_by_user_id=NEW.reviewed_by_user_id THEN
  RAISE EXCEPTION 'INDEPENDENT_LIFECYCLE_REVIEW_REQUIRED';
 ELSIF NEW.decision='APPROVE' AND e.source_action_recorded_by_user_id=NEW.reviewed_by_user_id THEN
  NEW.limitations='["SELF_ATTESTED","ACTION_AUTHOR_REVIEWED","PROVIDER_RETIREMENT_NOT_VERIFIED"]'::jsonb;
 ELSE
  NEW.limitations='["PROVIDER_RETIREMENT_NOT_VERIFIED"]'::jsonb;
 END IF;
 IF NEW.expected_evidence_version<>(SELECT 1+count(*) FROM secret_lifecycle_evidence_reviews WHERE evidence_id=e.evidence_id)
 THEN RAISE EXCEPTION 'STALE_LIFECYCLE_REVIEW'; END IF;
 IF NOT EXISTS(SELECT 1 FROM secret_case_occurrences WHERE case_id=e.case_id) OR EXISTS(
  SELECT 1 FROM secret_case_occurrences co JOIN secret_occurrences o USING(occurrence_id)
  WHERE co.case_id=e.case_id AND NOT EXISTS(SELECT 1 FROM secret_role_grants g WHERE g.user_id=NEW.reviewed_by_user_id
   AND g.role='SECURITY' AND g.revoked_at IS NULL AND (g.connection_id IS NULL OR g.connection_id=o.connection_id)))
 THEN RAISE EXCEPTION 'LIFECYCLE_REVIEW_PERMISSION_REQUIRED'; END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE VIEW secret_current_lifecycle_evidence AS
 SELECT e.evidence_id,e.case_id,e.credential_set_id,e.source_occurrence_id,e.origin,e.kind,e.performed_at,e.observed_at,
 CASE WHEN e.verification_level='PROVIDER_VERIFIED' THEN 'PROVIDER_VERIFIED'
      WHEN last.limitations @> '["SELF_ATTESTED"]'::jsonb THEN 'SELF_ATTESTED'
      ELSE 'APPROVED_MANUAL' END::varchar AS verification_level,
 1+COALESCE(r.review_count,0) AS version,
 coalesce(last.limitations @> '["ACTION_AUTHOR_REVIEWED"]'::jsonb,false) AS action_author_reviewed
 FROM secret_credential_lifecycle_evidence e
 LEFT JOIN LATERAL(SELECT count(*) AS review_count FROM secret_lifecycle_evidence_reviews WHERE evidence_id=e.evidence_id)r ON true
 LEFT JOIN LATERAL(SELECT decision,reason_code,limitations FROM secret_lifecycle_evidence_reviews WHERE evidence_id=e.evidence_id ORDER BY review_id DESC LIMIT 1)last ON true
 WHERE (e.verification_level='PROVIDER_VERIFIED' OR last.decision='APPROVE')
 AND NOT EXISTS(SELECT 1 FROM secret_validation_attempts v WHERE v.credential_set_id=e.credential_set_id
    AND v.result='VALID' AND v.reason_code='AUTHENTICATED' AND v.provider_checked_at>e.performed_at)
 AND (e.kind<>'FIXTURE_RETIRED' OR (NOT EXISTS(SELECT 1 FROM secret_confirmed_real_credentials real WHERE real.credential_set_id=e.credential_set_id)
   AND NOT EXISTS(SELECT 1 FROM secret_case_occurrences co JOIN secret_occurrences o USING(occurrence_id) WHERE co.case_id=e.case_id
    AND NOT EXISTS(SELECT 1 FROM secret_current_fixture_attestations a WHERE a.credential_set_id=e.credential_set_id AND a.scope_id=o.scope_id))));

CREATE FUNCTION secret_lifecycle_source_action_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE source_action secret_action_records%ROWTYPE;
DECLARE matches BIGINT;
BEGIN
 IF NEW.source_action_id IS NULL AND NEW.verification_method='EXTERNAL_RECORD' THEN
  SELECT count(*),min(a.action_id) INTO matches,NEW.source_action_id FROM secret_action_records a
   WHERE a.case_id=NEW.case_id AND a.occurrence_id=NEW.source_occurrence_id
    AND a.action_type IN ('ROTATED','REVOKED') AND(NEW.kind=a.action_type OR NEW.kind='FIXTURE_RETIRED')
    AND a.performed_at=NEW.performed_at AND a.evidence_ref=NEW.evidence_ref;
  IF matches>1 THEN RAISE EXCEPTION 'AMBIGUOUS_LIFECYCLE_SOURCE_ACTION'; END IF;
 END IF;
 IF NEW.source_action_id IS NOT NULL THEN
  SELECT * INTO STRICT source_action FROM secret_action_records WHERE action_id=NEW.source_action_id FOR SHARE;
  IF NEW.verification_method<>'EXTERNAL_RECORD' OR source_action.case_id<>NEW.case_id
   OR source_action.occurrence_id<>NEW.source_occurrence_id OR source_action.action_type NOT IN ('ROTATED','REVOKED')
   OR(NEW.kind<>source_action.action_type AND NEW.kind<>'FIXTURE_RETIRED')
   OR source_action.performed_at<>NEW.performed_at OR source_action.evidence_ref<>NEW.evidence_ref
   OR(NEW.source_action_recorded_by_user_id IS NOT NULL AND NEW.source_action_recorded_by_user_id<>source_action.recorded_by_user_id)
  THEN RAISE EXCEPTION 'LIFECYCLE_SOURCE_ACTION_MISMATCH'; END IF;
  NEW.source_action_recorded_by_user_id=source_action.recorded_by_user_id;
 ELSIF NEW.source_action_recorded_by_user_id IS NOT NULL THEN
  RAISE EXCEPTION 'LIFECYCLE_SOURCE_ACTION_MISMATCH';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER secret_lifecycle_source_action_guard BEFORE INSERT ON secret_credential_lifecycle_evidence
 FOR EACH ROW EXECUTE FUNCTION secret_lifecycle_source_action_guard();


-- Queue location rechecks together while keeping one executing collection per connection.
DROP INDEX uq_secret_job_active_connection;
CREATE UNIQUE INDEX uq_secret_job_active_full_scan ON secret_jobs(connection_id)
 WHERE kind='FULL_SCAN' AND status IN ('PENDING','LEASED');
CREATE UNIQUE INDEX uq_secret_job_leased_connection ON secret_jobs(connection_id)
 WHERE kind IN ('FULL_SCAN','REVALIDATE') AND status='LEASED';
CREATE OR REPLACE FUNCTION secret_collection_job_queue_guard() RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.kind NOT IN ('FULL_SCAN','REVALIDATE') OR NEW.status NOT IN ('PENDING','LEASED') THEN RETURN NEW; END IF;
 IF TG_OP='UPDATE' AND OLD.kind=NEW.kind AND OLD.connection_id=NEW.connection_id
   AND OLD.status IN ('PENDING','LEASED') THEN RETURN NEW; END IF;
 PERFORM 1 FROM secret_connections WHERE connection_id=NEW.connection_id FOR UPDATE;
 IF EXISTS(SELECT 1 FROM secret_jobs j WHERE j.connection_id=NEW.connection_id AND j.job_id<>NEW.job_id
   AND j.kind IN ('FULL_SCAN','REVALIDATE') AND j.status IN ('PENDING','LEASED')
   AND (NEW.kind='FULL_SCAN' OR j.kind='FULL_SCAN'))
 THEN RAISE EXCEPTION 'ACTIVE_COLLECTION_JOB_EXISTS'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER trg_secret_collection_job_queue BEFORE INSERT OR UPDATE OF status,kind,connection_id
 ON secret_jobs FOR EACH ROW EXECUTE FUNCTION secret_collection_job_queue_guard();

CREATE TABLE secret_revalidation_batches (
 batch_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 case_id BIGINT NOT NULL REFERENCES secret_response_cases(case_id),
 requested_by_user_id BIGINT NOT NULL REFERENCES dashboard_users(user_id),
 case_version BIGINT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE secret_revalidation_batch_items (
 batch_id BIGINT NOT NULL REFERENCES secret_revalidation_batches(batch_id),
 ordinal INTEGER NOT NULL CHECK(ordinal>=0),
 occurrence_id BIGINT NOT NULL,
 revalidation_id BIGINT REFERENCES secret_case_revalidations(revalidation_id),
 error_code VARCHAR(80),
 reason_code VARCHAR(100),
 PRIMARY KEY(batch_id,ordinal),
 UNIQUE(batch_id,occurrence_id),
 CHECK((revalidation_id IS NOT NULL)=(error_code IS NULL))
);

ALTER TABLE secret_response_cases ADD COLUMN inherit_unassigned BOOLEAN NOT NULL DEFAULT FALSE;
CREATE OR REPLACE FUNCTION secret_inherit_location_assignee() RETURNS TRIGGER LANGUAGE plpgsql AS $$
DECLARE c secret_response_cases%ROWTYPE;
DECLARE conn BIGINT;
DECLARE actor BIGINT;
BEGIN
 SELECT * INTO c FROM secret_response_cases WHERE case_id=NEW.case_id;
 IF NOT c.inherit_unassigned OR NOT c.is_current OR c.disposition<>'IN_SCOPE' OR c.action_status='RESOLVED'
    OR NEW.assigned_user_id IS NOT NULL OR NEW.assigned_team IS NOT NULL OR NEW.response_status='RESOLVED'
 THEN RETURN NEW; END IF;
 SELECT connection_id INTO conn FROM secret_occurrences WHERE occurrence_id=NEW.occurrence_id;
 IF c.assigned_user_id IS NOT NULL THEN
  IF NOT EXISTS(SELECT 1 FROM secret_role_grants WHERE user_id=c.assigned_user_id AND role='REMEDIATOR'
    AND revoked_at IS NULL AND (connection_id IS NULL OR connection_id=conn)) THEN RETURN NEW; END IF;
  IF c.assigned_team IS NOT NULL AND NOT EXISTS(SELECT 1 FROM secret_team_memberships
    WHERE user_id=c.assigned_user_id AND team_name=c.assigned_team AND removed_at IS NULL) THEN RETURN NEW; END IF;
 ELSIF c.assigned_team IS NULL OR NOT EXISTS(SELECT 1 FROM secret_team_memberships m
    JOIN secret_role_grants g ON g.user_id=m.user_id WHERE m.team_name=c.assigned_team AND m.removed_at IS NULL
      AND g.role='REMEDIATOR' AND g.revoked_at IS NULL AND (g.connection_id IS NULL OR g.connection_id=conn))
 THEN RETURN NEW; END IF;
 SELECT changed_by_user_id INTO actor FROM secret_assignment_history WHERE case_id=c.case_id ORDER BY assignment_id DESC LIMIT 1;
 IF actor IS NULL THEN RETURN NEW; END IF;
 UPDATE secret_case_occurrences SET assigned_user_id=c.assigned_user_id,assigned_team=c.assigned_team,version=version+1
  WHERE case_id=NEW.case_id AND occurrence_id=NEW.occurrence_id;
 INSERT INTO secret_location_activities(case_id,occurrence_id,activity_type,actor_user_id,case_version,occurrence_version,reason_code)
  VALUES(NEW.case_id,NEW.occurrence_id,'LOCATION_ASSIGNED',actor,c.version,NEW.version+1,'INITIAL_ASSIGNMENT');
 RETURN NEW;
END $$;
CREATE TRIGGER trg_secret_inherit_location_assignee AFTER INSERT ON secret_case_occurrences
 FOR EACH ROW EXECUTE FUNCTION secret_inherit_location_assignee();

DO $$ DECLARE prior TEXT; BEGIN
 SELECT pg_get_expr(conbin,conrelid) INTO prior FROM pg_constraint
 WHERE conrelid='secret_audit_events'::regclass AND conname='ck_secret_audit_event_type';
 ALTER TABLE secret_audit_events DROP CONSTRAINT ck_secret_audit_event_type;
 EXECUTE 'ALTER TABLE secret_audit_events ADD CONSTRAINT ck_secret_audit_event_type CHECK(('||prior||') OR event_type=''LOCATION_REVALIDATION_BATCH_REQUESTED'')';
END $$;
