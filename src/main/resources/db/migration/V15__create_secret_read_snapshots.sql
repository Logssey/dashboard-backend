-- Stable, permission-bound read models. Only approved public facts are copied here.
CREATE TABLE secret_snapshot_owner_locks (
    user_id BIGINT PRIMARY KEY REFERENCES dashboard_users(user_id),
    epoch BIGINT NOT NULL DEFAULT 0
);
CREATE TABLE secret_query_snapshots (
    snapshot_id UUID PRIMARY KEY,
    scope VARCHAR(20) NOT NULL CHECK (scope IN ('WORKBENCH','CURRENT_CASES','INVENTORY','HISTORY')),
    owner_user_id BIGINT NOT NULL REFERENCES dashboard_users(user_id),
    case_origin VARCHAR(20),
    as_of TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    authorization_revision VARCHAR(100) NOT NULL,
    scope_version_digest VARCHAR(100) NOT NULL,
    normalized_filters JSONB NOT NULL,
    filter_digest VARCHAR(100) NOT NULL,
    partial_coverage BOOLEAN,
    restricted_coverage BOOLEAN NOT NULL,
    coverage_status VARCHAR(30) NOT NULL,
    missing_sources JSONB NOT NULL DEFAULT '[]',
    retained_from TIMESTAMPTZ,
    history_complete BOOLEAN NOT NULL DEFAULT FALSE,
    CHECK (expires_at > created_at)
);
CREATE INDEX idx_secret_snapshot_owner_expiry ON secret_query_snapshots(owner_user_id, expires_at);
CREATE TABLE secret_snapshot_subjects (
    snapshot_id UUID NOT NULL REFERENCES secret_query_snapshots(snapshot_id) ON DELETE CASCADE,
    subject_type VARCHAR(30) NOT NULL,
    subject_id BIGINT NOT NULL,
    credential_set_id BIGINT,
    safe_sort_key VARCHAR(200) NOT NULL,
    safe_facts JSONB NOT NULL,
    subject_version VARCHAR(100),
    PRIMARY KEY (snapshot_id, subject_type, subject_id)
);
CREATE TABLE secret_snapshot_metrics (
    snapshot_id UUID NOT NULL REFERENCES secret_query_snapshots(snapshot_id) ON DELETE CASCADE,
    metric_key VARCHAR(80) NOT NULL,
    unit VARCHAR(30) NOT NULL,
    status VARCHAR(30) NOT NULL,
    value BIGINT,
    reason_code VARCHAR(80),
    applied_filters JSONB NOT NULL,
    not_applicable_filters JSONB NOT NULL,
    PRIMARY KEY(snapshot_id, metric_key),
    CHECK ((status = 'AVAILABLE' AND value >= 0) OR (status <> 'AVAILABLE' AND value IS NULL))
);
CREATE TABLE secret_snapshot_metric_memberships (
    snapshot_id UUID NOT NULL,
    metric_key VARCHAR(80) NOT NULL,
    subject_type VARCHAR(30) NOT NULL,
    subject_id BIGINT NOT NULL,
    PRIMARY KEY(snapshot_id, metric_key, subject_type, subject_id),
    FOREIGN KEY(snapshot_id, metric_key) REFERENCES secret_snapshot_metrics(snapshot_id, metric_key) ON DELETE CASCADE,
    FOREIGN KEY(snapshot_id, subject_type, subject_id) REFERENCES secret_snapshot_subjects(snapshot_id, subject_type, subject_id) ON DELETE CASCADE
);
