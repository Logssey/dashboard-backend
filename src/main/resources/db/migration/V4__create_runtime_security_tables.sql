-- Runtime security vertical slice: Falco RUN-001 ingestion, normalized events, grouped findings and sensor status.

CREATE TABLE runtime_sensors (
    sensor_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cluster_id VARCHAR(80) NOT NULL,
    node_name VARCHAR(120) NOT NULL,
    sensor_type VARCHAR(20) NOT NULL CHECK (sensor_type IN ('FALCO', 'TETRAGON')),
    version VARCHAR(80),
    driver VARCHAR(40),
    rule_set_version VARCHAR(80),
    status VARCHAR(20) NOT NULL CHECK (status IN ('HEALTHY', 'DEGRADED', 'OFFLINE', 'UNKNOWN')),
    last_heartbeat_at TIMESTAMPTZ,
    last_event_at TIMESTAMPTZ,
    queue_depth BIGINT CHECK (queue_depth IS NULL OR queue_depth >= 0),
    error_message VARCHAR(500),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_runtime_sensor_node UNIQUE (cluster_id, node_name, sensor_type)
);

CREATE TABLE runtime_assets (
    runtime_asset_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    asset_id BIGINT REFERENCES assets (asset_id) ON DELETE SET NULL,
    cluster_id VARCHAR(80) NOT NULL,
    namespace VARCHAR(120) NOT NULL,
    workload_kind VARCHAR(40),
    workload_name VARCHAR(200),
    pod_uid VARCHAR(80),
    pod_name VARCHAR(253) NOT NULL,
    container_id VARCHAR(160) NOT NULL,
    container_name VARCHAR(253),
    image VARCHAR(500),
    image_digest VARCHAR(160),
    node_name VARCHAR(120),
    service_account_name VARCHAR(253),
    security_context JSONB,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_to TIMESTAMPTZ,
    snapshot_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_runtime_asset_instance UNIQUE (cluster_id, namespace, pod_name, container_id)
);
CREATE INDEX idx_runtime_assets_workload ON runtime_assets (cluster_id, namespace, workload_name);
CREATE INDEX idx_runtime_assets_pod_uid ON runtime_assets (cluster_id, pod_uid) WHERE pod_uid IS NOT NULL;

CREATE TABLE runtime_raw_events (
    raw_event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cluster_id VARCHAR(80) NOT NULL,
    sensor_type VARCHAR(20) NOT NULL CHECK (sensor_type IN ('FALCO', 'TETRAGON')),
    sensor_id BIGINT REFERENCES runtime_sensors (sensor_id) ON DELETE SET NULL,
    source_event_id VARCHAR(160) NOT NULL,
    idempotency_key VARCHAR(200) NOT NULL,
    schema_version VARCHAR(80) NOT NULL,
    payload JSONB NOT NULL,
    masked_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    processing_status VARCHAR(30) NOT NULL CHECK (processing_status IN (
        'RECEIVED', 'IGNORED', 'NORMALIZED', 'ASSET_RESOLVED', 'ASSET_UNRESOLVED', 'GROUPED', 'FAILED'
    )),
    error_code VARCHAR(80),
    received_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_runtime_raw_event UNIQUE (cluster_id, sensor_type, idempotency_key)
);
CREATE INDEX idx_runtime_raw_events_received ON runtime_raw_events (received_at DESC);
CREATE INDEX idx_runtime_raw_events_status ON runtime_raw_events (processing_status, received_at DESC);

CREATE TABLE runtime_events (
    runtime_event_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    raw_event_id BIGINT NOT NULL UNIQUE REFERENCES runtime_raw_events (raw_event_id) ON DELETE RESTRICT,
    runtime_asset_id BIGINT REFERENCES runtime_assets (runtime_asset_id) ON DELETE SET NULL,
    source VARCHAR(20) NOT NULL CHECK (source IN ('FALCO', 'TETRAGON')),
    source_event_id VARCHAR(160) NOT NULL,
    event_type VARCHAR(40) NOT NULL,
    rule_key VARCHAR(40) NOT NULL,
    rule_version VARCHAR(40) NOT NULL,
    source_priority VARCHAR(20) NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    process_id BIGINT,
    parent_process_id BIGINT,
    process_executable VARCHAR(500),
    process_arguments JSONB NOT NULL DEFAULT '[]'::jsonb,
    parent_executable VARCHAR(500),
    user_id VARCHAR(40),
    normalization_status VARCHAR(20) NOT NULL CHECK (normalization_status IN ('COMPLETE', 'PARTIAL')),
    missing_fields JSONB NOT NULL DEFAULT '[]'::jsonb,
    asset_resolution_status VARCHAR(20) NOT NULL CHECK (asset_resolution_status IN ('PENDING', 'RESOLVED', 'UNRESOLVED')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_runtime_events_occurred ON runtime_events (occurred_at DESC);
CREATE INDEX idx_runtime_events_rule ON runtime_events (rule_key, occurred_at DESC);

CREATE TABLE runtime_findings (
    finding_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    display_id VARCHAR(20) GENERATED ALWAYS AS ('RTF-' || lpad(finding_id::text, 6, '0')) STORED UNIQUE,
    fingerprint VARCHAR(64) NOT NULL UNIQUE,
    rule_key VARCHAR(40) NOT NULL,
    rule_title VARCHAR(200) NOT NULL,
    rule_version VARCHAR(40) NOT NULL,
    runtime_asset_id BIGINT REFERENCES runtime_assets (runtime_asset_id) ON DELETE SET NULL,
    asset_id BIGINT REFERENCES assets (asset_id) ON DELETE SET NULL,
    source_priority VARCHAR(20) NOT NULL,
    final_severity VARCHAR(10) CHECK (final_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    evaluation_status VARCHAR(30) NOT NULL CHECK (evaluation_status IN (
        'PENDING_CONTEXT', 'EVALUATED', 'INSUFFICIENT_CONTEXT', 'EVALUATION_FAILED'
    )),
    review_status VARCHAR(20) NOT NULL DEFAULT 'UNREVIEWED' CHECK (review_status IN ('UNREVIEWED', 'REVIEWED')),
    action_status VARCHAR(20) NOT NULL DEFAULT 'OPEN' CHECK (action_status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'RISK_ACCEPTED')),
    disposition VARCHAR(30) NOT NULL DEFAULT 'UNDECIDED' CHECK (disposition IN ('UNDECIDED', 'EXPECTED', 'ACTION_REQUIRED')),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    occurrence_count BIGINT NOT NULL DEFAULT 1 CHECK (occurrence_count > 0),
    process_executable VARCHAR(500),
    parent_executable VARCHAR(500),
    user_id VARCHAR(40),
    assignee_user_id BIGINT REFERENCES dashboard_users (user_id) ON DELETE SET NULL,
    note TEXT,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_runtime_findings_last_seen ON runtime_findings (last_seen_at DESC);
CREATE INDEX idx_runtime_findings_review ON runtime_findings (review_status, last_seen_at DESC);
CREATE INDEX idx_runtime_findings_rule ON runtime_findings (rule_key, last_seen_at DESC);

CREATE TABLE runtime_finding_events (
    finding_id BIGINT NOT NULL REFERENCES runtime_findings (finding_id) ON DELETE CASCADE,
    runtime_event_id BIGINT NOT NULL UNIQUE REFERENCES runtime_events (runtime_event_id) ON DELETE RESTRICT,
    linked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (finding_id, runtime_event_id)
);

CREATE TABLE runtime_finding_history (
    history_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    finding_id BIGINT NOT NULL REFERENCES runtime_findings (finding_id) ON DELETE CASCADE,
    changed_by_user_id BIGINT REFERENCES dashboard_users (user_id) ON DELETE SET NULL,
    previous_review_status VARCHAR(20),
    next_review_status VARCHAR(20),
    previous_action_status VARCHAR(20),
    next_action_status VARCHAR(20),
    previous_disposition VARCHAR(30),
    next_disposition VARCHAR(30),
    previous_assignee_user_id BIGINT,
    next_assignee_user_id BIGINT,
    previous_note TEXT,
    next_note TEXT,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_runtime_finding_history ON runtime_finding_history (finding_id, changed_at DESC);
