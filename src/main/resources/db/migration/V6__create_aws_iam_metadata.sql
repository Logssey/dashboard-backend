-- IAM metadata is an inventory observation, not a recovered secret or validation result.
CREATE UNIQUE INDEX uq_secret_aws_metadata_identity
    ON secret_credential_sets (issuer, credential_type, issuer_connection_id, external_key_ref)
    WHERE component_state = 'METADATA_ONLY' AND issuer = 'AWS';

CREATE TABLE secret_aws_access_key_observations (
    credential_set_id BIGINT NOT NULL REFERENCES secret_credential_sets (credential_set_id),
    run_id BIGINT NOT NULL REFERENCES secret_scan_runs (run_id),
    key_status VARCHAR(10) NOT NULL CHECK (key_status IN ('ACTIVE', 'INACTIVE', 'EXPIRED', 'UNKNOWN')),
    issued_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    last_used_service VARCHAR(120),
    last_used_region VARCHAR(80),
    observed_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (credential_set_id, run_id)
);
