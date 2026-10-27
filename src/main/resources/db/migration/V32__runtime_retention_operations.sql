-- Raw payload lifecycle: retain integrity metadata while removing sensitive JSON after its retention period.

ALTER TABLE runtime_raw_events
    ADD COLUMN payload_sha256 VARCHAR(64),
    ADD COLUMN payload_retention_until TIMESTAMPTZ,
    ADD COLUMN payload_purged_at TIMESTAMPTZ,
    ADD CONSTRAINT ck_runtime_raw_payload_sha256 CHECK (
        payload_sha256 IS NULL OR payload_sha256 ~ '^[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT ck_runtime_raw_payload_retention CHECK (
        payload_retention_until IS NULL OR payload_retention_until >= received_at
    ),
    ADD CONSTRAINT ck_runtime_raw_payload_purged CHECK (
        payload_purged_at IS NULL
        OR (payload_retention_until IS NOT NULL AND payload_purged_at >= payload_retention_until)
    );

UPDATE runtime_raw_events
SET payload_retention_until = received_at + INTERVAL '30 days'
WHERE payload_retention_until IS NULL;

CREATE INDEX idx_runtime_raw_events_retention
    ON runtime_raw_events (payload_retention_until, raw_event_id)
    WHERE payload_purged_at IS NULL;

CREATE TABLE runtime_maintenance_runs (
    maintenance_run_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job_type VARCHAR(40) NOT NULL CHECK (job_type IN ('RETENTION')),
    triggered_by VARCHAR(20) NOT NULL CHECK (triggered_by IN ('SCHEDULE', 'USER')),
    actor_user_id BIGINT REFERENCES dashboard_users (user_id) ON DELETE SET NULL,
    payloads_purged BIGINT NOT NULL DEFAULT 0 CHECK (payloads_purged >= 0),
    rate_windows_deleted BIGINT NOT NULL DEFAULT 0 CHECK (rate_windows_deleted >= 0),
    remaining_payload_backlog BIGINT NOT NULL DEFAULT 0 CHECK (remaining_payload_backlog >= 0),
    started_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_runtime_maintenance_actor CHECK (
        (triggered_by = 'SCHEDULE' AND actor_user_id IS NULL)
        OR (triggered_by = 'USER' AND actor_user_id IS NOT NULL)
    ),
    CONSTRAINT ck_runtime_maintenance_time CHECK (completed_at >= started_at)
);
CREATE INDEX idx_runtime_maintenance_runs_latest
    ON runtime_maintenance_runs (job_type, completed_at DESC);
