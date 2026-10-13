-- Scheduler foundation only. Credential sets and REVALIDATE jobs are added with the collector later.
CREATE TABLE secret_connections (
    connection_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    provider VARCHAR(20) NOT NULL CHECK (provider IN ('AWS', 'KUBERNETES', 'GITHUB', 'NOTION')),
    display_name VARCHAR(200) NOT NULL,
    auth_ref VARCHAR(300) NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('ACTIVE', 'PAUSED', 'ERROR')),
    scope_version BIGINT NOT NULL CHECK (scope_version > 0),
    next_due_at TIMESTAMPTZ,
    last_collection_success_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_secret_connections_due ON secret_connections (next_due_at, connection_id)
    WHERE status = 'ACTIVE';

CREATE TABLE secret_connection_scopes (
    scope_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    connection_id BIGINT NOT NULL REFERENCES secret_connections (connection_id),
    scope_key VARCHAR(300) NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    content_type VARCHAR(80) NOT NULL,
    approved_ref VARCHAR(500) NOT NULL,
    history_limit VARCHAR(100),
    enabled BOOLEAN NOT NULL,
    classification_version VARCHAR(80),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_secret_connection_scope_revision UNIQUE (connection_id, scope_key, revision),
    CONSTRAINT uq_secret_scope_connection UNIQUE (scope_id, connection_id)
);
CREATE UNIQUE INDEX uq_secret_enabled_scope ON secret_connection_scopes (connection_id, scope_key)
    WHERE enabled;

CREATE TABLE secret_jobs (
    job_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind VARCHAR(20) NOT NULL CHECK (kind IN ('FULL_SCAN')),
    connection_id BIGINT NOT NULL REFERENCES secret_connections (connection_id),
    requested_by_user_id BIGINT REFERENCES dashboard_users (user_id),
    idempotency_key VARCHAR(120),
    scheduled_at TIMESTAMPTZ NOT NULL,
    available_at TIMESTAMPTZ NOT NULL,
    attempt_no INTEGER NOT NULL CHECK (attempt_no >= 0),
    max_attempts INTEGER NOT NULL CHECK (max_attempts > 0 AND attempt_no <= max_attempts),
    status VARCHAR(20) NOT NULL CHECK (status IN ('PENDING', 'LEASED', 'SUCCEEDED', 'FAILED', 'CANCELLED')),
    lease_owner VARCHAR(120),
    lease_until TIMESTAMPTZ,
    last_error_code VARCHAR(80),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMPTZ,
    CONSTRAINT uq_secret_job_connection UNIQUE (job_id, connection_id),
    CONSTRAINT ck_secret_job_lease CHECK (
        (status = 'LEASED' AND lease_owner IS NOT NULL AND lease_until IS NOT NULL)
        OR (status <> 'LEASED' AND lease_owner IS NULL AND lease_until IS NULL)
    ),
    CONSTRAINT ck_secret_job_finished CHECK (
        (status IN ('SUCCEEDED', 'FAILED', 'CANCELLED') AND finished_at IS NOT NULL)
        OR (status IN ('PENDING', 'LEASED') AND finished_at IS NULL)
    )
);
CREATE UNIQUE INDEX uq_secret_job_scheduled ON secret_jobs (connection_id, kind, scheduled_at)
    WHERE requested_by_user_id IS NULL;
CREATE UNIQUE INDEX uq_secret_job_idempotency ON secret_jobs (idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE UNIQUE INDEX uq_secret_job_active_connection ON secret_jobs (connection_id, kind)
    WHERE status IN ('PENDING', 'LEASED');
CREATE INDEX idx_secret_jobs_available ON secret_jobs (available_at, job_id) WHERE status = 'PENDING';

CREATE TABLE secret_scan_runs (
    run_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    job_id BIGINT NOT NULL UNIQUE,
    connection_id BIGINT NOT NULL REFERENCES secret_connections (connection_id),
    trigger_type VARCHAR(20) NOT NULL CHECK (trigger_type IN ('SCHEDULED', 'MANUAL')),
    scope_version BIGINT NOT NULL CHECK (scope_version > 0),
    scheduled_at TIMESTAMPTZ NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    collection_status VARCHAR(20) NOT NULL CHECK (collection_status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'PARTIAL', 'FAILED', 'SKIPPED')),
    detection_status VARCHAR(20) NOT NULL CHECK (detection_status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'PARTIAL', 'FAILED', 'SKIPPED')),
    validation_status VARCHAR(20) NOT NULL CHECK (validation_status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'PARTIAL', 'FAILED', 'SKIPPED')),
    result_status VARCHAR(20) NOT NULL CHECK (result_status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'PARTIAL', 'FAILED', 'SKIPPED')),
    failure_code VARCHAR(80),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_secret_run_job_connection FOREIGN KEY (job_id, connection_id)
        REFERENCES secret_jobs (job_id, connection_id),
    CONSTRAINT uq_secret_run_connection UNIQUE (run_id, connection_id)
);

CREATE TABLE secret_run_scopes (
    run_scope_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id BIGINT NOT NULL REFERENCES secret_scan_runs (run_id),
    scope_id BIGINT NOT NULL REFERENCES secret_connection_scopes (scope_id),
    collection_status VARCHAR(20) NOT NULL CHECK (collection_status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'PARTIAL', 'FAILED', 'SKIPPED')),
    object_count BIGINT CHECK (object_count >= 0),
    failure_code VARCHAR(80),
    unsupported_reason VARCHAR(120),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    CONSTRAINT uq_secret_run_scope UNIQUE (run_id, scope_id)
);
