-- Prowler 실행은 API 프로세스와 분리한다. Worker는 짧은 임대를 받아 실행하고,
-- token + generation이 모두 일치하는 결과만 완료 처리할 수 있다.
CREATE TABLE compliance_scan_jobs (
    job_id BIGSERIAL PRIMARY KEY,
    target_key VARCHAR(100) NOT NULL,
    environment VARCHAR(30) NOT NULL CHECK (environment IN ('prod', 'dev')),
    provider VARCHAR(30) NOT NULL CHECK (provider = 'aws'),
    status VARCHAR(20) NOT NULL CHECK (status IN ('QUEUED', 'LEASED', 'SUCCEEDED', 'FAILED', 'CANCELLED')),
    scope JSONB NOT NULL CHECK (jsonb_typeof(scope) = 'object'),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    max_attempts INTEGER NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 10),
    available_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_token UUID,
    lease_generation BIGINT NOT NULL DEFAULT 0 CHECK (lease_generation >= 0),
    lease_until TIMESTAMPTZ,
    worker_id VARCHAR(120),
    requested_by_login VARCHAR(120) NOT NULL,
    error_code VARCHAR(80),
    run_id BIGINT REFERENCES compliance_runs(run_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    CONSTRAINT compliance_scan_jobs_lease_state CHECK (
        (status = 'LEASED' AND lease_token IS NOT NULL AND lease_until IS NOT NULL AND worker_id IS NOT NULL)
        OR
        (status <> 'LEASED' AND lease_token IS NULL AND lease_until IS NULL AND worker_id IS NULL)
    ),
    CONSTRAINT compliance_scan_jobs_terminal_state CHECK (
        (status = 'SUCCEEDED' AND run_id IS NOT NULL AND finished_at IS NOT NULL)
        OR (status IN ('FAILED', 'CANCELLED') AND run_id IS NULL AND finished_at IS NOT NULL)
        OR (status IN ('QUEUED', 'LEASED') AND run_id IS NULL AND finished_at IS NULL)
    )
);

CREATE INDEX idx_compliance_scan_jobs_pending
    ON compliance_scan_jobs (available_at, job_id)
    WHERE status IN ('QUEUED', 'LEASED');

CREATE INDEX idx_compliance_scan_jobs_target_latest
    ON compliance_scan_jobs (target_key, created_at DESC, job_id DESC);
