-- First insertion provenance is never inferred from historical timestamps.
ALTER TABLE secret_credential_sets ADD COLUMN first_seen_run_id BIGINT REFERENCES secret_scan_runs(run_id);
CREATE INDEX idx_secret_first_seen_run ON secret_credential_sets(first_seen_run_id) WHERE first_seen_run_id IS NOT NULL;
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
