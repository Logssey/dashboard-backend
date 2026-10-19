-- A revalidation is an explicit, single-scope scan tied to an external action.
-- Its absence result is recorded only after complete collection and detection.
ALTER TABLE secret_jobs DROP CONSTRAINT secret_jobs_kind_check;
ALTER TABLE secret_jobs ADD CONSTRAINT ck_secret_job_kind
    CHECK (kind IN ('FULL_SCAN', 'REVALIDATE'));

ALTER TABLE secret_scan_runs DROP CONSTRAINT secret_scan_runs_trigger_type_check;
ALTER TABLE secret_scan_runs ADD CONSTRAINT ck_secret_run_trigger_type
    CHECK (trigger_type IN ('SCHEDULED', 'MANUAL', 'REVALIDATION'));

ALTER TABLE secret_case_stage_history DROP CONSTRAINT secret_case_stage_history_reason_code_check;
ALTER TABLE secret_case_stage_history ADD CONSTRAINT ck_secret_case_stage_reason CHECK (
    reason_code IN ('RESPONSE_STARTED', 'EXTERNAL_ACTION_RECORDED',
                    'REVALIDATION_PRESENT', 'POST_ACTION_REVALIDATION'));
ALTER TABLE secret_audit_events DROP CONSTRAINT ck_secret_audit_event_type;
ALTER TABLE secret_audit_events ADD CONSTRAINT ck_secret_audit_event_type CHECK (
    event_type IN ('CASE_OPENED', 'ASSIGNMENT_CHANGED', 'REVIEW_RECORDED',
                   'RESPONSE_STARTED', 'CHECKLIST_CHANGED', 'ACTION_RECORDED',
                   'REVALIDATION_REQUESTED', 'REVALIDATION_REOPENED', 'CASE_RESOLVED'));

-- A full scan and a case revalidation must not race on occurrence presence.
DROP INDEX uq_secret_job_active_connection;
CREATE UNIQUE INDEX uq_secret_job_active_connection ON secret_jobs (connection_id)
    WHERE status IN ('PENDING', 'LEASED');

CREATE TABLE secret_case_revalidations (
    revalidation_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES secret_response_cases (case_id),
    occurrence_id BIGINT NOT NULL REFERENCES secret_occurrences (occurrence_id),
    action_id BIGINT NOT NULL REFERENCES secret_action_records (action_id),
    connection_id BIGINT NOT NULL REFERENCES secret_connections (connection_id),
    scope_id BIGINT NOT NULL REFERENCES secret_connection_scopes (scope_id),
    job_id BIGINT NOT NULL UNIQUE REFERENCES secret_jobs (job_id),
    run_id BIGINT NOT NULL UNIQUE REFERENCES secret_scan_runs (run_id),
    requested_by_user_id BIGINT NOT NULL REFERENCES dashboard_users (user_id),
    idempotency_digest VARCHAR(65) NOT NULL,
    baseline_config_hash VARCHAR(100),
    baseline_engine_version VARCHAR(100),
    baseline_fingerprint_version VARCHAR(40) NOT NULL,
    runtime_fingerprint_version VARCHAR(40),
    case_version BIGINT NOT NULL CHECK (case_version > 0),
    status VARCHAR(20) NOT NULL DEFAULT 'PENDING'
        CHECK (status IN ('PENDING', 'PRESENT', 'MISSING', 'UNKNOWN')),
    failure_code VARCHAR(80),
    requested_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TIMESTAMPTZ,
    CONSTRAINT fk_secret_revalidation_case_occurrence FOREIGN KEY (case_id, occurrence_id)
        REFERENCES secret_case_occurrences (case_id, occurrence_id),
    CONSTRAINT uq_secret_case_revalidation_key UNIQUE (case_id, idempotency_digest)
);
CREATE INDEX idx_secret_case_revalidation_latest
    ON secret_case_revalidations (case_id, occurrence_id, requested_at DESC, revalidation_id DESC);

CREATE TABLE secret_case_resolutions (
    case_id BIGINT PRIMARY KEY REFERENCES secret_response_cases (case_id),
    resolved_by_user_id BIGINT NOT NULL REFERENCES dashboard_users (user_id),
    reason_code VARCHAR(80) NOT NULL CHECK (reason_code = 'POST_ACTION_REVALIDATION'),
    case_version BIGINT NOT NULL CHECK (case_version > 0),
    resolved_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE secret_case_resolution_locations (
    case_id BIGINT NOT NULL REFERENCES secret_case_resolutions (case_id),
    occurrence_id BIGINT NOT NULL REFERENCES secret_occurrences (occurrence_id),
    revalidation_id BIGINT NOT NULL REFERENCES secret_case_revalidations (revalidation_id),
    PRIMARY KEY (case_id, occurrence_id)
);

CREATE TABLE secret_case_resume_events (
    resume_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES secret_response_cases (case_id),
    occurrence_id BIGINT NOT NULL REFERENCES secret_occurrences (occurrence_id),
    revalidation_id BIGINT NOT NULL REFERENCES secret_case_revalidations (revalidation_id),
    resumed_by_user_id BIGINT NOT NULL REFERENCES dashboard_users (user_id),
    case_version BIGINT NOT NULL CHECK (case_version > 0),
    resumed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_secret_case_resume_version UNIQUE (case_id, case_version)
);
