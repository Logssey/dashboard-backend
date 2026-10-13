-- Safe validation history. Provider credentials and response bodies are never persisted.
ALTER TABLE secret_scan_runs
    ADD CONSTRAINT uq_secret_run_job UNIQUE (run_id, job_id);

CREATE TABLE secret_validation_attempts (
    attempt_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    credential_set_id BIGINT NOT NULL REFERENCES secret_credential_sets (credential_set_id),
    run_id BIGINT NOT NULL,
    job_id BIGINT NOT NULL,
    validator_id VARCHAR(120) NOT NULL,
    validator_version VARCHAR(80) NOT NULL,
    endpoint_class VARCHAR(80) NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ NOT NULL,
    provider_checked_at TIMESTAMPTZ,
    result VARCHAR(10) NOT NULL CHECK (result IN ('VALID', 'INVALID', 'UNKNOWN', 'UNCHECKED')),
    reason_code VARCHAR(80) NOT NULL CHECK (reason_code ~ '^[A-Z0-9_]{1,80}$'),
    next_due_at TIMESTAMPTZ,
    CONSTRAINT fk_secret_validation_run_job FOREIGN KEY (run_id, job_id)
        REFERENCES secret_scan_runs (run_id, job_id),
    CONSTRAINT ck_secret_validation_timestamps CHECK (
        completed_at >= requested_at AND
        (provider_checked_at IS NULL OR provider_checked_at BETWEEN requested_at AND completed_at)
    ),
    CONSTRAINT ck_secret_validation_checked CHECK (
        result NOT IN ('VALID', 'INVALID') OR provider_checked_at IS NOT NULL
    )
);
CREATE INDEX idx_secret_validation_latest
    ON secret_validation_attempts (credential_set_id, completed_at DESC, attempt_id DESC);
CREATE INDEX idx_secret_validation_run
    ON secret_validation_attempts (run_id, credential_set_id, attempt_id DESC);
