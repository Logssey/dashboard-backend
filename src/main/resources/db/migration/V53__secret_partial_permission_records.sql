-- Partial permission work is a revisable draft. Final decisions remain one-per-observation.
ALTER TABLE secret_permission_decisions DROP CONSTRAINT secret_permission_decisions_observation_id_key;
ALTER TABLE secret_permission_decisions DROP CONSTRAINT secret_permission_decisions_decision_check;
ALTER TABLE secret_permission_decisions DROP CONSTRAINT secret_permission_decisions_check;
ALTER TABLE secret_permission_decisions ADD CONSTRAINT ck_secret_permission_decision
 CHECK(decision IN('CONFIRMED','REJECTED','DRAFTED'));
ALTER TABLE secret_permission_decisions ADD CONSTRAINT ck_secret_permission_decision_evidence
 CHECK((decision IN('CONFIRMED','DRAFTED'))=(evidence_id IS NOT NULL));
CREATE UNIQUE INDEX uq_secret_permission_final_decision ON secret_permission_decisions(observation_id)
 WHERE decision IN('CONFIRMED','REJECTED');
CREATE INDEX idx_secret_permission_decision_history ON secret_permission_decisions(observation_id,decision_id DESC);

-- Optional storage setup becomes actionable when current credential evidence needs a decision.
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
     CASE WHEN binding_id IS NULL AND EXISTS(SELECT 1 FROM secret_current_valid_findings raw
       JOIN secret_occurrences found ON found.occurrence_id=raw.occurrence_id
       JOIN secret_credential_sets credential ON credential.credential_set_id=found.credential_set_id
       WHERE found.scope_id=basis.scope_id AND credential.component_state='CONFIRMED') THEN 'POLICY_MISSING'
       WHEN binding_id IS NULL THEN NULL
       WHEN policy_status<>'ACTIVE' THEN 'POLICY_RETIRED'
       WHEN valid_from>now() THEN 'POLICY_NOT_YET_VALID'
       WHEN valid_until<=now() THEN 'POLICY_EXPIRED'
       WHEN NOT policy_matches THEN 'POLICY_SCOPE_MISMATCH' END END
 ],NULL)::text[] AS setup_reason_codes FROM basis
)
SELECT scope_id,cardinality(setup_reason_codes)>0 AS needs_review,setup_reason_codes FROM reasons;


-- A chosen default is pinned to an approved policy version; its existing rules authorize each scope.
CREATE TABLE secret_connection_policy_defaults (
 connection_id BIGINT PRIMARY KEY REFERENCES secret_connections,
 policy_id BIGINT NOT NULL,
 policy_version BIGINT NOT NULL,
 selected_by_user_id BIGINT NOT NULL REFERENCES dashboard_users,
 selected_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(policy_id,policy_version) REFERENCES secret_storage_policies(policy_id,version)
);
