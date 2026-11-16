-- Prowler OCSF 결과를 원본 대신 정규화된 점검 근거로 보관한다.
CREATE TABLE compliance_runs (
    run_id BIGSERIAL PRIMARY KEY,
    target_key VARCHAR(100) NOT NULL,
    environment VARCHAR(30) NOT NULL CHECK (environment IN ('prod', 'dev')),
    status VARCHAR(30) NOT NULL CHECK (status IN ('COMPLETED', 'COMPLETED_WITH_WARNINGS')),
    source VARCHAR(50) NOT NULL,
    product VARCHAR(100) NOT NULL,
    scanner_version VARCHAR(50) NOT NULL,
    artifact_sha256 CHAR(64) NOT NULL,
    input_count INTEGER NOT NULL CHECK (input_count >= 0),
    result_count INTEGER NOT NULL CHECK (result_count >= 0),
    duplicate_count INTEGER NOT NULL CHECK (duplicate_count >= 0),
    warning_count INTEGER NOT NULL CHECK (warning_count >= 0),
    pass_count INTEGER NOT NULL CHECK (pass_count >= 0),
    fail_count INTEGER NOT NULL CHECK (fail_count >= 0),
    error_count INTEGER NOT NULL CHECK (error_count >= 0),
    needs_review_count INTEGER NOT NULL CHECK (needs_review_count >= 0),
    created_by_login VARCHAR(120) NOT NULL,
    finished_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_compliance_runs_latest
    ON compliance_runs (target_key, environment, finished_at DESC, run_id DESC);

CREATE TABLE compliance_results (
    result_id BIGSERIAL PRIMARY KEY,
    run_id BIGINT NOT NULL REFERENCES compliance_runs(run_id) ON DELETE CASCADE,
    check_id VARCHAR(180) NOT NULL,
    title VARCHAR(500) NOT NULL,
    provider VARCHAR(30) NOT NULL,
    result VARCHAR(30) NOT NULL CHECK (result IN ('PASS', 'FAIL', 'ERROR', 'NEEDS_REVIEW')),
    asset VARCHAR(500) NOT NULL,
    current_value TEXT NOT NULL,
    expected_value TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    region VARCHAR(100) NOT NULL,
    severity VARCHAR(30) NOT NULL,
    fingerprint VARCHAR(700) NOT NULL,
    asset_uid VARCHAR(700) NOT NULL,
    asset_type VARCHAR(180) NOT NULL,
    UNIQUE (run_id, fingerprint)
);

CREATE INDEX idx_compliance_results_run_result
    ON compliance_results (run_id, result, severity);
CREATE INDEX idx_compliance_results_run_check
    ON compliance_results (run_id, provider, check_id);

CREATE TABLE compliance_control_assessments (
    run_id BIGINT NOT NULL REFERENCES compliance_runs(run_id) ON DELETE CASCADE,
    framework_id VARCHAR(30) NOT NULL,
    control_id VARCHAR(80) NOT NULL,
    status VARCHAR(40) NOT NULL CHECK (status IN ('TECHNICAL_FAIL', 'TECHNICALLY_SATISFIED', 'NEEDS_REVIEW', 'NOT_ASSESSED')),
    mapped_check_count INTEGER NOT NULL CHECK (mapped_check_count >= 0),
    observed_check_count INTEGER NOT NULL CHECK (observed_check_count >= 0),
    failed_check_count INTEGER NOT NULL CHECK (failed_check_count >= 0),
    PRIMARY KEY (run_id, framework_id, control_id)
);

CREATE INDEX idx_compliance_assessments_run_framework_status
    ON compliance_control_assessments (run_id, framework_id, status);
