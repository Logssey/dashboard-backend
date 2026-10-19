-- A review is an assessment of the response case, not a provider-side key change.
-- Free-form notes and source content are deliberately absent from these tables.
CREATE TABLE secret_case_reviews (
    review_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES secret_response_cases (case_id),
    decision VARCHAR(30) NOT NULL CHECK (decision IN ('CONFIRMED', 'NEEDS_MORE_INFO')),
    reason_code VARCHAR(40) NOT NULL,
    reviewed_by_user_id BIGINT NOT NULL REFERENCES dashboard_users (user_id),
    reviewed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    case_version BIGINT NOT NULL CHECK (case_version > 0),
    CONSTRAINT ck_secret_case_review_reason CHECK (
        (decision = 'CONFIRMED' AND reason_code = 'EVIDENCE_CONFIRMED') OR
        (decision = 'NEEDS_MORE_INFO' AND reason_code = 'INSUFFICIENT_EVIDENCE')
    ),
    CONSTRAINT uq_secret_case_review_version UNIQUE (case_id, case_version)
);
CREATE INDEX idx_secret_case_reviews_case_time
    ON secret_case_reviews (case_id, reviewed_at DESC, review_id DESC);

CREATE TABLE secret_checklist_items (
    item_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES secret_response_cases (case_id),
    guide_version VARCHAR(80) NOT NULL CHECK (guide_version = 'S2_V1'),
    item_code VARCHAR(80) NOT NULL CHECK (item_code IN (
        'IDENTIFY_OWNER', 'ROTATE_OR_REVOKE', 'REMOVE_EXPOSURE', 'CHECK_ACCESS_LOGS'
    )),
    status VARCHAR(20) NOT NULL DEFAULT 'TODO' CHECK (status IN ('TODO', 'DONE')),
    completed_at TIMESTAMPTZ,
    completed_by_user_id BIGINT REFERENCES dashboard_users (user_id),
    evidence_ref VARCHAR(71),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_secret_checklist_item UNIQUE (case_id, guide_version, item_code),
    CONSTRAINT ck_secret_checklist_completion CHECK (
        (status = 'TODO' AND completed_at IS NULL AND completed_by_user_id IS NULL
            AND evidence_ref IS NULL)
        OR (status = 'DONE' AND completed_at IS NOT NULL AND completed_by_user_id IS NOT NULL
            AND evidence_ref ~ '^(TICKET|CHANGE):[A-Z]{2,10}-[1-9][0-9]{0,9}$')
    )
);
CREATE INDEX idx_secret_checklist_case ON secret_checklist_items (case_id, item_id);

CREATE TABLE secret_checklist_history (
    history_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES secret_response_cases (case_id),
    item_id BIGINT NOT NULL REFERENCES secret_checklist_items (item_id),
    from_status VARCHAR(20) NOT NULL CHECK (from_status IN ('TODO', 'DONE')),
    to_status VARCHAR(20) NOT NULL CHECK (to_status IN ('TODO', 'DONE')),
    evidence_ref VARCHAR(71),
    changed_by_user_id BIGINT NOT NULL REFERENCES dashboard_users (user_id),
    changed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    case_version BIGINT NOT NULL CHECK (case_version > 0),
    CONSTRAINT uq_secret_checklist_history_version UNIQUE (case_id, case_version),
    CONSTRAINT ck_secret_checklist_history_evidence CHECK (
        (to_status = 'TODO' AND evidence_ref IS NULL) OR
        (to_status = 'DONE' AND evidence_ref ~ '^(TICKET|CHANGE):[A-Z]{2,10}-[1-9][0-9]{0,9}$')
    )
);
CREATE INDEX idx_secret_checklist_history_item_time
    ON secret_checklist_history (item_id, changed_at DESC, history_id DESC);

CREATE TABLE secret_action_records (
    action_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    case_id BIGINT NOT NULL,
    occurrence_id BIGINT NOT NULL,
    action_type VARCHAR(40) NOT NULL CHECK (action_type IN (
        'ROTATED', 'REVOKED', 'REMOVED_FROM_SOURCE', 'PERMISSION_REDUCED'
    )),
    performed_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    recorded_by_user_id BIGINT NOT NULL REFERENCES dashboard_users (user_id),
    evidence_ref VARCHAR(71) NOT NULL
        CHECK (evidence_ref ~ '^(TICKET|CHANGE):[A-Z]{2,10}-[1-9][0-9]{0,9}$'),
    case_version BIGINT NOT NULL CHECK (case_version > 0),
    CONSTRAINT fk_secret_action_case_occurrence FOREIGN KEY (case_id, occurrence_id)
        REFERENCES secret_case_occurrences (case_id, occurrence_id),
    CONSTRAINT uq_secret_action_version UNIQUE (case_id, case_version)
);
CREATE INDEX idx_secret_action_case_time
    ON secret_action_records (case_id, recorded_at DESC, action_id DESC);

CREATE TABLE secret_case_stage_history (
    stage_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    case_id BIGINT NOT NULL REFERENCES secret_response_cases (case_id),
    from_status VARCHAR(30) NOT NULL CHECK (from_status IN (
        'OPEN', 'IN_PROGRESS', 'REVALIDATION_PENDING', 'RESOLVED'
    )),
    to_status VARCHAR(30) NOT NULL CHECK (to_status IN (
        'OPEN', 'IN_PROGRESS', 'REVALIDATION_PENDING', 'RESOLVED'
    )),
    reason_code VARCHAR(40) NOT NULL CHECK (reason_code IN (
        'RESPONSE_STARTED', 'EXTERNAL_ACTION_RECORDED'
    )),
    actor_user_id BIGINT NOT NULL REFERENCES dashboard_users (user_id),
    changed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    case_version BIGINT NOT NULL CHECK (case_version > 0),
    CONSTRAINT uq_secret_case_stage_version UNIQUE (case_id, case_version)
);

ALTER TABLE secret_audit_events
    DROP CONSTRAINT secret_audit_events_event_type_check;
ALTER TABLE secret_audit_events
    ADD CONSTRAINT ck_secret_audit_event_type CHECK (event_type IN (
        'CASE_OPENED', 'ASSIGNMENT_CHANGED', 'REVIEW_RECORDED', 'RESPONSE_STARTED',
        'CHECKLIST_CHANGED', 'ACTION_RECORDED'
    ));

INSERT INTO secret_checklist_items (case_id, guide_version, item_code)
SELECT c.case_id, 'S2_V1', codes.item_code
FROM secret_response_cases c
CROSS JOIN (VALUES ('IDENTIFY_OWNER'), ('ROTATE_OR_REVOKE'),
                   ('REMOVE_EXPOSURE'), ('CHECK_ACCESS_LOGS')) codes(item_code)
WHERE c.is_current
ON CONFLICT (case_id, guide_version, item_code) DO NOTHING;
