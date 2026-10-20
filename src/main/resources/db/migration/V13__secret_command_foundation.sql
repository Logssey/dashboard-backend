-- Extend shared command infrastructure without rewriting any previously applied migration.
CREATE TABLE secret_command_idempotency (
    command_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_user_id BIGINT NOT NULL REFERENCES dashboard_users (user_id),
    command_kind VARCHAR(80) NOT NULL,
    idempotency_key VARCHAR(120) NOT NULL,
    safe_request_digest BYTEA NOT NULL CHECK (octet_length(safe_request_digest) = 32),
    safe_result JSONB NOT NULL CHECK (jsonb_typeof(safe_result) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_secret_command_actor_kind_key UNIQUE (actor_user_id, command_kind, idempotency_key)
);

-- Existing case audit inserts remain valid. New commands can identify a run or scope instead.
ALTER TABLE secret_audit_events
    ALTER COLUMN case_id DROP NOT NULL,
    ALTER COLUMN case_version DROP NOT NULL,
    ADD COLUMN target_type VARCHAR(40),
    ADD COLUMN target_id BIGINT CHECK (target_id > 0),
    ADD COLUMN target_version BIGINT CHECK (target_version >= 0),
    ADD COLUMN command_id BIGINT REFERENCES secret_command_idempotency (command_id),
    ADD COLUMN safe_changes JSONB NOT NULL DEFAULT '{}'::JSONB
        CHECK (jsonb_typeof(safe_changes) = 'object');

UPDATE secret_audit_events
SET target_type = 'CASE', target_id = case_id, target_version = case_version;

ALTER TABLE secret_audit_events
    DROP CONSTRAINT ck_secret_audit_event_type,
    ADD CONSTRAINT ck_secret_audit_event_type CHECK (event_type IN (
        'CASE_OPENED', 'ASSIGNMENT_CHANGED', 'REVIEW_RECORDED', 'RESPONSE_STARTED',
        'CHECKLIST_CHANGED', 'ACTION_RECORDED', 'REVALIDATION_REQUESTED',
        'CASE_RESOLVED', 'REVALIDATION_REOPENED', 'MANUAL_SCAN_REGISTERED'
    ));
CREATE UNIQUE INDEX uq_secret_audit_command ON secret_audit_events (command_id)
    WHERE command_id IS NOT NULL;
CREATE INDEX idx_secret_audit_target_time
    ON secret_audit_events (target_type, target_id, occurred_at DESC, audit_id DESC);
