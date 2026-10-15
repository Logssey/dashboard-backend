-- Existing scopes and occurrences remain unassessed until a SECURITY user records a decision.
ALTER TABLE secret_connection_scopes
    ADD COLUMN response_origin_version BIGINT NOT NULL DEFAULT 0
        CHECK (response_origin_version >= 0);
ALTER TABLE secret_occurrences
    ADD COLUMN exposure_assessment_version BIGINT NOT NULL DEFAULT 0
        CHECK (exposure_assessment_version >= 0);

CREATE TABLE secret_scope_origin_decisions (
    decision_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scope_id BIGINT NOT NULL REFERENCES secret_connection_scopes (scope_id),
    from_origin VARCHAR(20) NOT NULL CHECK (from_origin = 'UNCLASSIFIED'),
    to_origin VARCHAR(20) NOT NULL CHECK (to_origin IN ('TEST', 'PRODUCTION')),
    reason_code VARCHAR(40) NOT NULL,
    actor_user_id BIGINT NOT NULL REFERENCES dashboard_users (user_id),
    decided_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version BIGINT NOT NULL CHECK (version = 1),
    CONSTRAINT ck_secret_scope_origin_reason CHECK (
        (to_origin = 'TEST' AND reason_code = 'APPROVED_TEST_FIXTURE') OR
        (to_origin = 'PRODUCTION' AND reason_code = 'APPROVED_PRODUCTION_SOURCE')
    ),
    CONSTRAINT uq_secret_scope_origin_decision_version UNIQUE (scope_id, version)
);

-- Findings are re-created by detector retries. Keep an immutable identifier and rule snapshot
-- instead of a foreign key that would block safe retry cleanup.
CREATE TABLE secret_exposure_assessments (
    assessment_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurrence_id BIGINT NOT NULL REFERENCES secret_occurrences (occurrence_id),
    finding_id BIGINT NOT NULL,
    finding_rule_id VARCHAR(120) NOT NULL,
    finding_run_id BIGINT NOT NULL,
    from_status VARCHAR(20) NOT NULL CHECK (from_status IN ('UNKNOWN', 'NORMAL', 'ABNORMAL')),
    decision VARCHAR(20) NOT NULL CHECK (decision IN ('NORMAL', 'ABNORMAL')),
    reason_code VARCHAR(40) NOT NULL,
    scope_origin VARCHAR(20) NOT NULL CHECK (scope_origin IN ('TEST', 'PRODUCTION')),
    actor_user_id BIGINT NOT NULL REFERENCES dashboard_users (user_id),
    assessed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    version BIGINT NOT NULL CHECK (version > 0),
    CONSTRAINT ck_secret_exposure_assessment_reason CHECK (
        (decision = 'NORMAL' AND reason_code = 'AUTHORIZED_LOCATION') OR
        (decision = 'ABNORMAL' AND reason_code = 'UNAPPROVED_SOURCE_LOCATION') OR
        (decision = 'ABNORMAL' AND reason_code = 'SIMULATED_EXPOSURE' AND scope_origin = 'TEST')
    ),
    CONSTRAINT uq_secret_exposure_assessment_version UNIQUE (occurrence_id, version)
);
CREATE INDEX idx_secret_exposure_assessments_occurrence_time
    ON secret_exposure_assessments (occurrence_id, assessed_at DESC, assessment_id DESC);
