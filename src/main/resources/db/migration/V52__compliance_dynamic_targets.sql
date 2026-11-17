-- 점검 대상과 AWS 역할 연결을 런타임 설정에서 분리한다. External ID는 서버가 생성하며
-- 사용자가 수정할 수 없다. 정적 AWS 자격 증명은 저장하지 않는다.
CREATE TABLE compliance_targets (
    target_key VARCHAR(100) PRIMARY KEY,
    display_name VARCHAR(120) NOT NULL,
    provider VARCHAR(30) NOT NULL CHECK (provider = 'aws'),
    aws_account_id VARCHAR(12) NOT NULL CHECK (aws_account_id ~ '^[0-9]{12}$'),
    role_arn VARCHAR(620) NOT NULL UNIQUE,
    external_id VARCHAR(100) NOT NULL UNIQUE,
    default_regions JSONB NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(default_regions) = 'array'),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    connection_status VARCHAR(20) NOT NULL DEFAULT 'NOT_TESTED'
        CHECK (connection_status IN ('NOT_TESTED', 'VERIFYING', 'VERIFIED', 'FAILED')),
    connection_error_code VARCHAR(80),
    connection_checked_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version >= 1),
    created_by_login VARCHAR(120) NOT NULL,
    updated_by_login VARCHAR(120) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_compliance_targets_display_name
    ON compliance_targets (display_name, target_key);

ALTER TABLE compliance_scan_jobs
    ADD COLUMN job_kind VARCHAR(30) NOT NULL DEFAULT 'ASSESSMENT'
        CHECK (job_kind IN ('ASSESSMENT', 'CONNECTION_TEST')),
    ADD COLUMN target_version BIGINT,
    ADD COLUMN target_account_id VARCHAR(12),
    ADD COLUMN target_role_arn VARCHAR(620),
    ADD COLUMN target_external_id VARCHAR(100),
    ADD COLUMN verified_account_id VARCHAR(12);

ALTER TABLE compliance_scan_jobs DROP CONSTRAINT compliance_scan_jobs_terminal_state;
ALTER TABLE compliance_scan_jobs ADD CONSTRAINT compliance_scan_jobs_terminal_state CHECK (
    (status = 'SUCCEEDED'
        AND finished_at IS NOT NULL
        AND ((job_kind = 'ASSESSMENT' AND run_id IS NOT NULL)
             OR (job_kind = 'CONNECTION_TEST' AND run_id IS NULL AND verified_account_id IS NOT NULL)))
    OR (status IN ('FAILED', 'CANCELLED') AND run_id IS NULL AND finished_at IS NOT NULL)
    OR (status IN ('QUEUED', 'LEASED') AND run_id IS NULL AND finished_at IS NULL)
);

CREATE INDEX idx_compliance_scan_jobs_kind_pending
    ON compliance_scan_jobs (job_kind, available_at, job_id)
    WHERE status IN ('QUEUED', 'LEASED');

CREATE UNIQUE INDEX uq_compliance_connection_test_active
    ON compliance_scan_jobs (target_key)
    WHERE job_kind = 'CONNECTION_TEST' AND status IN ('QUEUED', 'LEASED');
