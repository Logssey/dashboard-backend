-- First insertion provenance is never inferred from historical timestamps.
ALTER TABLE secret_credential_sets ADD COLUMN first_seen_run_id BIGINT REFERENCES secret_scan_runs(run_id);
CREATE INDEX idx_secret_first_seen_run ON secret_credential_sets(first_seen_run_id) WHERE first_seen_run_id IS NOT NULL;
ALTER TABLE secret_connection_scopes ADD COLUMN alias_version BIGINT NOT NULL DEFAULT 0;
CREATE TABLE secret_snapshot_retirements (
    snapshot_id UUID PRIMARY KEY,
    owner_user_id BIGINT NOT NULL REFERENCES dashboard_users(user_id),
    retired_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE VIEW secret_scope_governance_status AS
SELECT s.scope_id,
 (s.response_origin='UNCLASSIFIED'
 OR EXISTS(SELECT 1 FROM secret_scope_classification_proposals p WHERE p.scope_id=s.scope_id AND p.status='PENDING_APPROVAL')
 OR NOT EXISTS(SELECT 1 FROM secret_scope_origin_decisions d WHERE d.scope_id=s.scope_id AND d.version=s.response_origin_version AND d.decision='APPROVED')
 OR (s.content_type IN ('GITHUB_REPOSITORY_FILES','AWS_SECRETS_MANAGER_VALUE','AWS_SSM_PARAMETER_VALUE','AWS_S3_OBJECT_CONTENT') AND NOT EXISTS(
   SELECT 1 FROM secret_scope_policy_bindings b JOIN secret_storage_policies p ON p.policy_id=b.policy_id AND p.version=b.policy_version
   JOIN secret_storage_policy_rules r ON r.policy_id=p.policy_id AND r.policy_version=p.version
   WHERE b.scope_id=s.scope_id AND b.effective_until IS NULL AND p.status='ACTIVE' AND p.valid_from<=now() AND (p.valid_until IS NULL OR p.valid_until>now())
     AND r.scope_id=s.scope_id AND r.scope_revision=s.revision AND r.scope_fingerprint=md5(jsonb_build_array(s.content_type,s.approved_ref,s.history_limit)::text)
 ))) AS needs_review
FROM secret_connection_scopes s;
CREATE TABLE secret_scope_alias_history (
    alias_change_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scope_id BIGINT NOT NULL REFERENCES secret_connection_scopes(scope_id),
    safe_display_alias VARCHAR(80),
    changed_by_user_id BIGINT NOT NULL REFERENCES dashboard_users(user_id),
    changed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    scope_revision BIGINT NOT NULL
);
DO $$ DECLARE old_expression TEXT; BEGIN
 SELECT pg_get_expr(conbin,conrelid) INTO old_expression FROM pg_constraint
 WHERE conrelid='secret_audit_events'::regclass AND conname='ck_secret_audit_event_type';
 EXECUTE 'ALTER TABLE secret_audit_events DROP CONSTRAINT ck_secret_audit_event_type';
 EXECUTE 'ALTER TABLE secret_audit_events ADD CONSTRAINT ck_secret_audit_event_type CHECK (('
   ||old_expression||') OR event_type=''SCOPE_ALIAS_CHANGED'')';
END $$;
