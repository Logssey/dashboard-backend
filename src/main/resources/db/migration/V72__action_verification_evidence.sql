-- Absence is usable only when the specific successful check that observed it is known.
ALTER TABLE iac_attack_paths ADD COLUMN checked_job_id BIGINT REFERENCES iac_jobs(job_id);
ALTER TABLE iac_findings ADD COLUMN checked_job_id BIGINT REFERENCES iac_jobs(job_id);
ALTER TABLE iac_findings ADD COLUMN checked_run_id BIGINT REFERENCES iac_runs(run_id);
-- No backfill: last_seen_at is a discovery time, not proof of a subsequent successful check.
CREATE TABLE security_action_verifications (
    verification_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind VARCHAR(20) NOT NULL CHECK (kind = 'IMAGE'),
    target_id BIGINT NOT NULL,
    action_version BIGINT NOT NULL,
    scan_id BIGINT NOT NULL REFERENCES reach_scans(scan_id),
    actor_user_id BIGINT NOT NULL REFERENCES dashboard_users(user_id),
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY(kind,target_id) REFERENCES security_action_records(kind,target_id) ON DELETE CASCADE
);
