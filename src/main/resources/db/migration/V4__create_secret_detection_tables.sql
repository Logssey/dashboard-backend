-- Secret identity and detection results. Raw credentials and detector output never enter these tables.
CREATE TABLE secret_credential_sets (
    credential_set_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    issuer VARCHAR(40) NOT NULL,
    credential_type VARCHAR(80) NOT NULL,
    component_state VARCHAR(20) NOT NULL
        CHECK (component_state IN ('CONFIRMED', 'CANDIDATE', 'METADATA_ONLY')),
    issuer_connection_id BIGINT REFERENCES secret_connections (connection_id),
    fingerprint BYTEA,
    candidate_locator BYTEA,
    fingerprint_key_version VARCHAR(40),
    masked_label VARCHAR(120),
    external_key_ref VARCHAR(300),
    owner_ref VARCHAR(200),
    purpose_label VARCHAR(200),
    issued_at TIMESTAMPTZ,
    expiry_policy VARCHAR(10) NOT NULL DEFAULT 'UNKNOWN'
        CHECK (expiry_policy IN ('FIXED', 'NEVER', 'UNKNOWN')),
    expires_at TIMESTAMPTZ,
    lifecycle_status VARCHAR(20) NOT NULL DEFAULT 'UNKNOWN'
        CHECK (lifecycle_status IN ('ACTIVE', 'EXPIRED', 'REVOKED', 'UNKNOWN')),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_secret_credential_identity CHECK (
        (component_state = 'CONFIRMED' AND fingerprint IS NOT NULL AND candidate_locator IS NULL
            AND fingerprint_key_version IS NOT NULL)
        OR (component_state = 'CANDIDATE' AND fingerprint IS NULL AND candidate_locator IS NOT NULL
            AND fingerprint_key_version IS NOT NULL)
        OR (component_state = 'METADATA_ONLY' AND fingerprint IS NULL AND candidate_locator IS NULL)
    ),
    CONSTRAINT ck_secret_credential_expiry CHECK (expiry_policy <> 'FIXED' OR expires_at IS NOT NULL),
    CONSTRAINT ck_secret_credential_seen CHECK (last_seen_at >= first_seen_at)
);
CREATE UNIQUE INDEX uq_secret_fingerprint
    ON secret_credential_sets (issuer, credential_type, fingerprint_key_version, fingerprint)
    WHERE component_state = 'CONFIRMED';
-- A candidate is stable only at its own source location, even if its partial value matches elsewhere.
CREATE UNIQUE INDEX uq_secret_candidate_locator
    ON secret_credential_sets (fingerprint_key_version, candidate_locator)
    WHERE component_state = 'CANDIDATE';

CREATE TABLE secret_occurrences (
    occurrence_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    credential_set_id BIGINT NOT NULL REFERENCES secret_credential_sets (credential_set_id),
    connection_id BIGINT NOT NULL REFERENCES secret_connections (connection_id),
    scope_id BIGINT NOT NULL,
    asset_id BIGINT REFERENCES assets (asset_id),
    source_object_ref VARCHAR(500) NOT NULL,
    location_key VARCHAR(500) NOT NULL,
    latest_object_version VARCHAR(200),
    environment VARCHAR(10) NOT NULL CHECK (environment IN ('PROD', 'DEV', 'UNKNOWN')),
    exposure_status VARCHAR(10) NOT NULL CHECK (exposure_status IN ('ABNORMAL', 'NORMAL', 'UNKNOWN')),
    exposure_range VARCHAR(10) NOT NULL CHECK (exposure_range IN ('BROAD', 'BOUNDED', 'UNKNOWN')),
    presence_status VARCHAR(10) NOT NULL CHECK (presence_status IN ('PRESENT', 'MISSING', 'UNKNOWN')),
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_run_id BIGINT,
    last_complete_coverage_at TIMESTAMPTZ,
    CONSTRAINT fk_secret_occurrence_scope_connection FOREIGN KEY (scope_id, connection_id)
        REFERENCES secret_connection_scopes (scope_id, connection_id),
    CONSTRAINT fk_secret_occurrence_run_connection FOREIGN KEY (last_seen_run_id, connection_id)
        REFERENCES secret_scan_runs (run_id, connection_id),
    CONSTRAINT uq_secret_occurrence_location UNIQUE
        (credential_set_id, connection_id, source_object_ref, location_key),
    CONSTRAINT ck_secret_occurrence_seen CHECK (last_seen_at >= first_seen_at)
);
CREATE INDEX idx_secret_occurrences_connection_presence
    ON secret_occurrences (connection_id, scope_id, presence_status, last_seen_at DESC);

CREATE TABLE secret_tool_runs (
    tool_run_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_scope_id BIGINT NOT NULL REFERENCES secret_run_scopes (run_scope_id),
    engine VARCHAR(20) NOT NULL CHECK (engine IN ('GITLEAKS', 'TRUFFLEHOG')),
    engine_version VARCHAR(100) NOT NULL,
    config_hash VARCHAR(100) NOT NULL,
    status VARCHAR(20) NOT NULL CHECK (status IN ('PENDING', 'RUNNING', 'SUCCEEDED', 'PARTIAL', 'FAILED', 'SKIPPED')),
    finding_count BIGINT CHECK (finding_count >= 0),
    failure_code VARCHAR(80),
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    CONSTRAINT uq_secret_tool_run_scope_engine UNIQUE (run_scope_id, engine)
);

CREATE TABLE secret_findings (
    finding_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurrence_id BIGINT NOT NULL REFERENCES secret_occurrences (occurrence_id),
    run_id BIGINT NOT NULL REFERENCES secret_scan_runs (run_id),
    tool_run_id BIGINT NOT NULL REFERENCES secret_tool_runs (tool_run_id),
    finding_key VARCHAR(100) NOT NULL,
    rule_id VARCHAR(120) NOT NULL,
    rule_version VARCHAR(100) NOT NULL,
    masked_context TEXT,
    detected_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_secret_finding_tool_key UNIQUE (tool_run_id, finding_key)
);
CREATE INDEX idx_secret_findings_occurrence ON secret_findings (occurrence_id, detected_at DESC);
