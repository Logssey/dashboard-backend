ALTER TABLE secret_scope_classification_proposals
    ADD COLUMN approval_mode VARCHAR(30) NOT NULL DEFAULT 'INDEPENDENT_REVIEW'
        CHECK (approval_mode IN ('DIRECT','INDEPENDENT_REVIEW')),
    ADD COLUMN approval_rule_version VARCHAR(80) NOT NULL DEFAULT 'legacy-independent-v1',
    ADD COLUMN reviewer_user_id BIGINT REFERENCES dashboard_users(user_id),
    ADD CONSTRAINT ck_secret_reviewer_independent CHECK (reviewer_user_id IS NULL OR reviewer_user_id <> proposed_by_user_id);
ALTER TABLE secret_scope_origin_decisions
    ADD COLUMN approval_mode VARCHAR(30) CHECK (approval_mode IN ('DIRECT','INDEPENDENT_REVIEW')),
    ADD COLUMN approval_rule_version VARCHAR(80);

-- Reasons are computed from current facts; keeping one unfinished reason is not a failed save.
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
   CASE WHEN response_origin='UNCLASSIFIED' THEN 'SOURCE_UNCLASSIFIED' END,
   CASE WHEN response_origin<>'UNCLASSIFIED' AND NOT decided THEN 'CLASSIFICATION_EVIDENCE_REQUIRED' END,
   CASE WHEN pending THEN 'PENDING_REVIEW' END,
   CASE WHEN impact_pending THEN 'CLASSIFICATION_IMPACT_PENDING' END,
   CASE WHEN content_type IN ('GITHUB_REPOSITORY_FILES','AWS_SECRETS_MANAGER_VALUE','AWS_SSM_PARAMETER_VALUE','AWS_S3_OBJECT_CONTENT') THEN
     CASE WHEN binding_id IS NULL THEN 'POLICY_MISSING'
       WHEN policy_status<>'ACTIVE' THEN 'POLICY_RETIRED'
       WHEN valid_from>now() THEN 'POLICY_NOT_YET_VALID'
       WHEN valid_until<=now() THEN 'POLICY_EXPIRED'
       WHEN NOT policy_matches THEN 'POLICY_SCOPE_MISMATCH' END END
 ],NULL)::text[] AS setup_reason_codes FROM basis
)
SELECT scope_id,cardinality(setup_reason_codes)>0 AS needs_review,setup_reason_codes FROM reasons;

DO $$ DECLARE expression TEXT; BEGIN
 SELECT pg_get_expr(conbin,conrelid) INTO expression FROM pg_constraint
 WHERE conrelid='secret_audit_events'::regclass AND conname='ck_secret_audit_event_type';
 ALTER TABLE secret_audit_events DROP CONSTRAINT ck_secret_audit_event_type;
 EXECUTE 'ALTER TABLE secret_audit_events ADD CONSTRAINT ck_secret_audit_event_type CHECK (('
   ||expression||') OR event_type=''CLASSIFICATION_REVIEWER_ASSIGNED'')';
END $$;
