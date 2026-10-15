-- Response cases are opened only after a separately evidenced abnormal exposure.
-- No existing inventory row is backfilled into a response case by this migration.
ALTER TABLE secret_occurrences
    ADD CONSTRAINT uq_secret_occurrence_credential_pair UNIQUE (occurrence_id, credential_set_id);

-- Existing scopes are deliberately unclassified. Incident origin requires separate approval.
ALTER TABLE secret_connection_scopes
    ADD COLUMN response_origin VARCHAR(20) NOT NULL DEFAULT 'UNCLASSIFIED'
        CHECK (response_origin IN ('UNCLASSIFIED', 'PRODUCTION', 'TEST')),
    ADD COLUMN response_origin_set_by_user_id BIGINT REFERENCES dashboard_users (user_id),
    ADD COLUMN response_origin_set_at TIMESTAMPTZ,
    ADD CONSTRAINT ck_secret_scope_response_origin_audit CHECK (
        (response_origin = 'UNCLASSIFIED' AND response_origin_set_by_user_id IS NULL
            AND response_origin_set_at IS NULL)
        OR (response_origin <> 'UNCLASSIFIED' AND response_origin_set_by_user_id IS NOT NULL
            AND response_origin_set_at IS NOT NULL)
    );

CREATE TABLE secret_response_cases (
    case_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    credential_set_id BIGINT NOT NULL REFERENCES secret_credential_sets (credential_set_id),
    previous_case_id BIGINT REFERENCES secret_response_cases (case_id),
    opening_occurrence_id BIGINT NOT NULL,
    opened_by_user_id BIGINT NOT NULL REFERENCES dashboard_users (user_id),
    opening_reason VARCHAR(80) NOT NULL,
    case_origin VARCHAR(20) NOT NULL CHECK (case_origin IN ('PRODUCTION', 'TEST')),
    is_current BOOLEAN NOT NULL DEFAULT TRUE,
    disposition VARCHAR(20) NOT NULL DEFAULT 'IN_SCOPE'
        CHECK (disposition IN ('IN_SCOPE', 'FALSE_POSITIVE', 'OUT_OF_SCOPE')),
    action_status VARCHAR(30) NOT NULL DEFAULT 'OPEN'
        CHECK (action_status IN ('OPEN', 'IN_PROGRESS', 'REVALIDATION_PENDING', 'RESOLVED')),
    review_status VARCHAR(20) NOT NULL DEFAULT 'UNREVIEWED'
        CHECK (review_status IN ('UNREVIEWED', 'REVIEWED')),
    assigned_team VARCHAR(100),
    assigned_user_id BIGINT REFERENCES dashboard_users (user_id),
    version BIGINT NOT NULL DEFAULT 0 CHECK (version >= 0),
    opened_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMPTZ,
    closed_at TIMESTAMPTZ,
    CONSTRAINT ck_secret_case_current_closed CHECK (is_current OR closed_at IS NOT NULL),
    CONSTRAINT fk_secret_case_opening_identity FOREIGN KEY (opening_occurrence_id, credential_set_id)
        REFERENCES secret_occurrences (occurrence_id, credential_set_id),
    CONSTRAINT uq_secret_case_credential_pair UNIQUE (case_id, credential_set_id)
);
CREATE UNIQUE INDEX uq_secret_current_case_per_credential_origin
    ON secret_response_cases (credential_set_id, case_origin) WHERE is_current;
CREATE INDEX idx_secret_response_cases_current_updated
    ON secret_response_cases (case_origin, updated_at DESC, case_id DESC) WHERE is_current;

CREATE TABLE secret_case_occurrences (
    case_id BIGINT NOT NULL,
    occurrence_id BIGINT NOT NULL,
    credential_set_id BIGINT NOT NULL,
    response_status VARCHAR(30) NOT NULL DEFAULT 'OPEN'
        CHECK (response_status IN ('OPEN', 'IN_PROGRESS', 'REVALIDATION_PENDING', 'RESOLVED')),
    linked_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMPTZ,
    PRIMARY KEY (case_id, occurrence_id),
    CONSTRAINT fk_secret_case_occurrence_case_identity FOREIGN KEY (case_id, credential_set_id)
        REFERENCES secret_response_cases (case_id, credential_set_id),
    CONSTRAINT fk_secret_case_occurrence_source_identity FOREIGN KEY (occurrence_id, credential_set_id)
        REFERENCES secret_occurrences (occurrence_id, credential_set_id)
);

CREATE TABLE secret_assignment_history (
    assignment_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES secret_response_cases (case_id),
    from_team VARCHAR(100),
    to_team VARCHAR(100),
    from_user_id BIGINT REFERENCES dashboard_users (user_id),
    to_user_id BIGINT REFERENCES dashboard_users (user_id),
    reason VARCHAR(80) NOT NULL,
    changed_by_user_id BIGINT NOT NULL REFERENCES dashboard_users (user_id),
    changed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    case_version BIGINT NOT NULL CHECK (case_version > 0),
    CONSTRAINT uq_secret_assignment_version UNIQUE (case_id, case_version)
);
CREATE INDEX idx_secret_assignment_case_time
    ON secret_assignment_history (case_id, changed_at DESC, assignment_id DESC);

CREATE TABLE secret_audit_events (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES secret_response_cases (case_id),
    event_type VARCHAR(30) NOT NULL CHECK (event_type IN ('CASE_OPENED', 'ASSIGNMENT_CHANGED')),
    actor_user_id BIGINT NOT NULL REFERENCES dashboard_users (user_id),
    case_version BIGINT NOT NULL CHECK (case_version >= 0),
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_secret_audit_case_version_type UNIQUE (case_id, case_version, event_type)
);
CREATE INDEX idx_secret_audit_case_time ON secret_audit_events (case_id, occurred_at DESC);

CREATE TABLE secret_role_grants (
    grant_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES dashboard_users (user_id),
    role VARCHAR(30) NOT NULL CHECK (role IN ('SECURITY', 'REMEDIATOR', 'OPERATIONS')),
    connection_id BIGINT REFERENCES secret_connections (connection_id),
    granted_by_user_id BIGINT NOT NULL REFERENCES dashboard_users (user_id),
    grant_source VARCHAR(20) NOT NULL CHECK (grant_source IN ('BOOTSTRAP', 'MANUAL')),
    granted_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_secret_global_role_grant
    ON secret_role_grants (user_id, role) WHERE revoked_at IS NULL AND connection_id IS NULL;
CREATE UNIQUE INDEX uq_secret_scoped_role_grant
    ON secret_role_grants (user_id, role, connection_id)
    WHERE revoked_at IS NULL AND connection_id IS NOT NULL;

CREATE TABLE secret_team_memberships (
    membership_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id BIGINT NOT NULL REFERENCES dashboard_users (user_id),
    team_name VARCHAR(100) NOT NULL,
    added_by_user_id BIGINT NOT NULL REFERENCES dashboard_users (user_id),
    added_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    removed_at TIMESTAMPTZ
);
CREATE UNIQUE INDEX uq_secret_active_team_membership
    ON secret_team_memberships (user_id, team_name) WHERE removed_at IS NULL;
