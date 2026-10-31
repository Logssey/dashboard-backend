-- Shared ingestion windows protect all backend replicas from a noisy sensor or rule.

CREATE TABLE runtime_ingest_rate_windows (
    cluster_id VARCHAR(80) NOT NULL,
    node_name VARCHAR(120) NOT NULL,
    rule_key VARCHAR(40) NOT NULL REFERENCES runtime_rules (rule_key) ON DELETE RESTRICT,
    window_started_at TIMESTAMPTZ NOT NULL,
    received_count BIGINT NOT NULL DEFAULT 0 CHECK (received_count >= 0),
    processed_count BIGINT NOT NULL DEFAULT 0 CHECK (processed_count >= 0),
    rate_limited_count BIGINT NOT NULL DEFAULT 0 CHECK (rate_limited_count >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (cluster_id, node_name, rule_key, window_started_at),
    CONSTRAINT ck_runtime_rate_window_counts CHECK (
        received_count = processed_count + rate_limited_count
    )
);
CREATE INDEX idx_runtime_ingest_rate_windows_updated
    ON runtime_ingest_rate_windows (updated_at DESC);

ALTER TABLE runtime_raw_events
    DROP CONSTRAINT runtime_raw_events_processing_status_check;
ALTER TABLE runtime_raw_events
    ADD CONSTRAINT runtime_raw_events_processing_status_check CHECK (processing_status IN (
        'RECEIVED', 'IGNORED', 'NORMALIZED', 'ASSET_RESOLVED', 'ASSET_UNRESOLVED',
        'GROUPED', 'SUPPRESSED', 'RATE_LIMITED', 'FAILED'
    ));
