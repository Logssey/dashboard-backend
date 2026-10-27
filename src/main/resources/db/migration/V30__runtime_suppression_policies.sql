-- Auditable, time-bounded suppression policies. Suppressed events remain available as evidence.

CREATE TABLE runtime_suppressions (
    suppression_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_key VARCHAR(40) NOT NULL REFERENCES runtime_rules (rule_key) ON DELETE RESTRICT,
    cluster_id VARCHAR(80) NOT NULL,
    namespace VARCHAR(120),
    workload_name VARCHAR(200),
    process_executable VARCHAR(500),
    target_name_prefix VARCHAR(1000),
    operation VARCHAR(40),
    reason_code VARCHAR(40) NOT NULL CHECK (reason_code IN (
        'APPROVED_OPERATION', 'PLATFORM_COMPONENT', 'TEMPORARY_MAINTENANCE'
    )),
    evidence_ref VARCHAR(80) NOT NULL CHECK (
        evidence_ref ~ '^(TICKET|CHANGE):[A-Z][A-Z0-9]{1,15}-[1-9][0-9]{0,12}$'
    ),
    comment VARCHAR(500) NOT NULL,
    created_by_user_id BIGINT NOT NULL REFERENCES dashboard_users (user_id) ON DELETE RESTRICT,
    idempotency_key VARCHAR(100) NOT NULL,
    request_digest VARCHAR(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_by_user_id BIGINT REFERENCES dashboard_users (user_id) ON DELETE RESTRICT,
    revoked_at TIMESTAMPTZ,
    revoke_reason VARCHAR(500),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    CONSTRAINT uq_runtime_suppression_idempotency UNIQUE (created_by_user_id, idempotency_key),
    CONSTRAINT ck_runtime_suppression_specific_scope CHECK (
        num_nonnulls(namespace, workload_name, process_executable, target_name_prefix) > 0
    ),
    CONSTRAINT ck_runtime_suppression_expiry CHECK (
        expires_at > created_at AND expires_at <= created_at + INTERVAL '30 days'
    ),
    CONSTRAINT ck_runtime_suppression_revocation CHECK (
        (revoked_at IS NULL AND revoked_by_user_id IS NULL AND revoke_reason IS NULL)
        OR (revoked_at IS NOT NULL AND revoked_by_user_id IS NOT NULL AND revoke_reason IS NOT NULL)
    )
);
CREATE INDEX idx_runtime_suppressions_match
    ON runtime_suppressions (rule_key, cluster_id, expires_at)
    WHERE revoked_at IS NULL;

ALTER TABLE runtime_events
    ADD COLUMN handling_status VARCHAR(20) NOT NULL DEFAULT 'GROUPED'
        CHECK (handling_status IN ('GROUPED', 'SUPPRESSED')),
    ADD COLUMN suppression_id BIGINT REFERENCES runtime_suppressions (suppression_id) ON DELETE RESTRICT;

ALTER TABLE runtime_events
    ADD CONSTRAINT ck_runtime_event_suppression CHECK (
        (handling_status = 'GROUPED' AND suppression_id IS NULL)
        OR (handling_status = 'SUPPRESSED' AND suppression_id IS NOT NULL)
    );
CREATE INDEX idx_runtime_events_suppressed
    ON runtime_events (suppression_id, occurred_at DESC)
    WHERE handling_status = 'SUPPRESSED';

ALTER TABLE runtime_raw_events
    DROP CONSTRAINT runtime_raw_events_processing_status_check;
ALTER TABLE runtime_raw_events
    ADD CONSTRAINT runtime_raw_events_processing_status_check CHECK (processing_status IN (
        'RECEIVED', 'IGNORED', 'NORMALIZED', 'ASSET_RESOLVED', 'ASSET_UNRESOLVED',
        'GROUPED', 'SUPPRESSED', 'FAILED'
    ));
