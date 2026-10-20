CREATE SEQUENCE secret_storage_policy_id_seq;
CREATE TABLE secret_storage_policies (
    policy_id BIGINT NOT NULL DEFAULT nextval('secret_storage_policy_id_seq'),
    version BIGINT NOT NULL CHECK (version > 0),
    status VARCHAR(20) NOT NULL CHECK (status IN ('DRAFT','ACTIVE','RETIRED')),
    reason_code VARCHAR(80) NOT NULL,
    evidence_ref VARCHAR(120) NOT NULL
        CHECK (evidence_ref ~ '^((TICKET|CHANGE):[A-Z]{2,10}-[1-9][0-9]{0,9}|POLICY:SECRET-[1-9][0-9]{0,9})$'),
    created_by_user_id BIGINT NOT NULL REFERENCES dashboard_users(user_id),
    approved_by_user_id BIGINT REFERENCES dashboard_users(user_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ,
    approved_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,
    PRIMARY KEY (policy_id,version),
    CHECK (valid_until IS NULL OR valid_until > valid_from),
    CHECK (approved_by_user_id IS NULL OR approved_by_user_id <> created_by_user_id),
    CHECK (status <> 'ACTIVE' OR (approved_by_user_id IS NOT NULL AND approved_at IS NOT NULL))
);
CREATE UNIQUE INDEX uq_secret_policy_pending_draft ON secret_storage_policies(policy_id)
    WHERE status='DRAFT';
CREATE TABLE secret_storage_policy_rules (
    rule_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    policy_id BIGINT NOT NULL,
    policy_version BIGINT NOT NULL,
    effect VARCHAR(10) NOT NULL CHECK (effect IN ('ALLOW','DENY')),
    connection_id BIGINT NOT NULL REFERENCES secret_connections(connection_id),
    scope_id BIGINT NOT NULL,
    scope_revision BIGINT NOT NULL,
    scope_fingerprint VARCHAR(32) NOT NULL,
    content_type VARCHAR(80) NOT NULL,
    branch_condition VARCHAR(200),
    path_match VARCHAR(10) NOT NULL CHECK (path_match IN ('SCOPE','EXACT','PREFIX')),
    protected_path_condition VARCHAR(500),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (policy_id,policy_version) REFERENCES secret_storage_policies(policy_id,version),
    FOREIGN KEY (scope_id,connection_id) REFERENCES secret_connection_scopes(scope_id,connection_id),
    CHECK ((path_match='SCOPE' AND protected_path_condition IS NULL AND branch_condition IS NULL)
        OR (path_match IN ('EXACT','PREFIX') AND protected_path_condition IS NOT NULL AND branch_condition IS NOT NULL))
);
CREATE INDEX idx_secret_policy_rules_scope ON secret_storage_policy_rules(scope_id,policy_id,policy_version);

CREATE TABLE secret_scope_classification_proposals (
    proposal_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scope_id BIGINT NOT NULL REFERENCES secret_connection_scopes(scope_id),
    expected_scope_version BIGINT NOT NULL CHECK (expected_scope_version >= 0),
    scope_revision BIGINT NOT NULL,
    scope_fingerprint VARCHAR(32) NOT NULL,
    proposed_origin VARCHAR(20) NOT NULL CHECK (proposed_origin IN ('TEST','PRODUCTION')),
    policy_id BIGINT,
    policy_version BIGINT,
    reason_code VARCHAR(80) NOT NULL,
    evidence_ref VARCHAR(120) NOT NULL
        CHECK (evidence_ref ~ '^((TICKET|CHANGE):[A-Z]{2,10}-[1-9][0-9]{0,9}|POLICY:SECRET-[1-9][0-9]{0,9})$'),
    proposed_by_user_id BIGINT NOT NULL REFERENCES dashboard_users(user_id),
    status VARCHAR(30) NOT NULL CHECK (status IN ('PENDING_APPROVAL','APPROVED','REJECTED')),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (policy_id,policy_version) REFERENCES secret_storage_policies(policy_id,version),
    CHECK ((policy_id IS NULL)=(policy_version IS NULL)),
    CHECK ((policy_id IS NULL AND reason_code='POLICY_PENDING') OR policy_id IS NOT NULL)
);
CREATE UNIQUE INDEX uq_secret_scope_pending_proposal ON secret_scope_classification_proposals(scope_id)
    WHERE status='PENDING_APPROVAL';
ALTER TABLE secret_scope_classification_proposals
    ADD CONSTRAINT uq_secret_proposal_scope UNIQUE (proposal_id,scope_id);

-- Retain legacy decisions and their provenance, while allowing explicit corrections and rejection history.
ALTER TABLE secret_scope_origin_decisions
    DROP CONSTRAINT secret_scope_origin_decisions_from_origin_check,
    DROP CONSTRAINT secret_scope_origin_decisions_version_check,
    DROP CONSTRAINT ck_secret_scope_origin_reason,
    ALTER COLUMN reason_code TYPE VARCHAR(80),
    ADD COLUMN proposal_id BIGINT REFERENCES secret_scope_classification_proposals(proposal_id),
    ADD COLUMN evidence_ref VARCHAR(120),
    ADD COLUMN decision VARCHAR(20) NOT NULL DEFAULT 'LEGACY',
    ADD CONSTRAINT ck_secret_origin_from CHECK (from_origin IN ('UNCLASSIFIED','TEST','PRODUCTION')),
    ADD CONSTRAINT ck_secret_origin_version CHECK (version > 0),
    ADD CONSTRAINT ck_secret_origin_decision CHECK (decision IN ('LEGACY','APPROVED','REJECTED')),
    ADD CONSTRAINT ck_secret_origin_provenance CHECK (
        (decision='LEGACY' AND proposal_id IS NULL)
        OR (decision IN ('APPROVED','REJECTED') AND proposal_id IS NOT NULL AND evidence_ref IS NOT NULL)
    );
ALTER TABLE secret_scope_origin_decisions
    ADD CONSTRAINT uq_secret_origin_decision_scope UNIQUE (decision_id,scope_id),
    ADD CONSTRAINT fk_secret_origin_proposal_scope FOREIGN KEY (proposal_id,scope_id)
        REFERENCES secret_scope_classification_proposals(proposal_id,scope_id);

CREATE TABLE secret_scope_policy_bindings (
    binding_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scope_id BIGINT NOT NULL REFERENCES secret_connection_scopes(scope_id),
    scope_revision BIGINT NOT NULL,
    scope_origin_version BIGINT NOT NULL,
    scope_fingerprint VARCHAR(32) NOT NULL,
    policy_id BIGINT NOT NULL,
    policy_version BIGINT NOT NULL,
    classification_decision_id BIGINT NOT NULL REFERENCES secret_scope_origin_decisions(decision_id),
    effective_from TIMESTAMPTZ NOT NULL DEFAULT now(),
    effective_until TIMESTAMPTZ,
    FOREIGN KEY (policy_id,policy_version) REFERENCES secret_storage_policies(policy_id,version),
    FOREIGN KEY (classification_decision_id,scope_id) REFERENCES secret_scope_origin_decisions(decision_id,scope_id),
    CHECK (effective_until IS NULL OR effective_until >= effective_from)
);
CREATE UNIQUE INDEX uq_secret_scope_current_binding ON secret_scope_policy_bindings(scope_id)
    WHERE effective_until IS NULL;
CREATE TABLE secret_scope_classification_impacts (
    impact_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    decision_id BIGINT NOT NULL REFERENCES secret_scope_origin_decisions(decision_id),
    occurrence_id BIGINT NOT NULL REFERENCES secret_occurrences(occurrence_id),
    case_id BIGINT REFERENCES secret_response_cases(case_id),
    previous_origin VARCHAR(20) NOT NULL,
    new_origin VARCHAR(20) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE secret_occurrences
    ADD COLUMN policy_assessed_binding_id BIGINT REFERENCES secret_scope_policy_bindings(binding_id),
    ADD COLUMN policy_assessed_origin_version BIGINT,
    ADD COLUMN policy_recheck_required BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE secret_audit_events DROP CONSTRAINT ck_secret_audit_event_type;
ALTER TABLE secret_audit_events ADD CONSTRAINT ck_secret_audit_event_type CHECK (event_type IN (
    'CASE_OPENED','ASSIGNMENT_CHANGED','REVIEW_RECORDED','RESPONSE_STARTED','CHECKLIST_CHANGED',
    'ACTION_RECORDED','REVALIDATION_REQUESTED','REVALIDATION_REOPENED','CASE_RESOLVED',
    'MANUAL_SCAN_REGISTERED','POLICY_DRAFTED','POLICY_APPROVED','POLICY_RETIRED',
    'CLASSIFICATION_PROPOSED','CLASSIFICATION_APPROVED','CLASSIFICATION_REJECTED'
));

-- This view computes current applicability; neither expiration nor changed scope is a cached ALLOW.
CREATE VIEW secret_occurrence_policy_results AS
WITH scope_basis AS (
    SELECT o.occurrence_id,o.scope_id,o.source_object_ref,o.exposure_status,
           o.policy_assessed_binding_id,o.policy_assessed_origin_version,o.policy_recheck_required,
           s.connection_id,s.revision,s.response_origin,s.response_origin_version,s.enabled,
           s.content_type,s.history_limit,s.approved_ref,
           md5(jsonb_build_array(s.content_type,s.approved_ref,s.history_limit)::text) AS fingerprint,
           regexp_match(s.approved_ref,'^github://([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+)/([^/?#]+)/(.+/)$') AS github,
           b.binding_id,b.scope_revision AS bound_revision,b.scope_origin_version AS bound_origin_version,
           b.scope_fingerprint AS bound_fingerprint,b.policy_id,b.policy_version,
           p.status,p.valid_from,p.valid_until
    FROM secret_occurrences o
    JOIN secret_connection_scopes s ON s.scope_id=o.scope_id
    LEFT JOIN secret_scope_policy_bindings b ON b.scope_id=s.scope_id
        AND b.effective_until IS NULL AND b.effective_from <= now()
    LEFT JOIN secret_storage_policies p ON p.policy_id=b.policy_id AND p.version=b.policy_version
), matched AS (
    SELECT basis.*,
        COALESCE(rules.allow_count,0) AS allow_count,COALESCE(rules.deny_count,0) AS deny_count
    FROM scope_basis basis
    LEFT JOIN LATERAL (
        SELECT COUNT(*) FILTER (WHERE r.effect='ALLOW') AS allow_count,
               COUNT(*) FILTER (WHERE r.effect='DENY') AS deny_count
        FROM secret_storage_policy_rules r
        WHERE r.policy_id=basis.policy_id AND r.policy_version=basis.policy_version
          AND r.connection_id=basis.connection_id AND r.scope_id=basis.scope_id
          AND r.scope_revision=basis.revision AND r.scope_fingerprint=basis.fingerprint
          AND r.content_type=basis.content_type
          AND (
              (basis.content_type='GITHUB_REPOSITORY_FILES' AND basis.history_limit='CURRENT_COMMIT_ONLY'
               AND basis.github IS NOT NULL
               AND starts_with(basis.source_object_ref,basis.github[1] || '/' || basis.github[2] || '/' || basis.github[4])
               AND basis.source_object_ref !~ '(^|/)\.\.(/|$)'
               AND (r.path_match='SCOPE' OR
                    (r.branch_condition=basis.github[3] AND (
                        (r.path_match='EXACT' AND basis.source_object_ref=basis.github[1] || '/' || basis.github[2] || '/' || r.protected_path_condition)
                        OR (r.path_match='PREFIX' AND starts_with(basis.source_object_ref,basis.github[1] || '/' || basis.github[2] || '/' || r.protected_path_condition))
                    ))))
              OR (basis.content_type IN ('AWS_SECRETS_MANAGER_VALUE','AWS_SSM_PARAMETER_VALUE','AWS_S3_OBJECT_CONTENT')
                  AND basis.history_limit='CURRENT_VALUE_ONLY' AND r.path_match='SCOPE'
                  AND basis.approved_ref ~ '^aws://[0-9]{12}/[a-z0-9-]+/(secrets-manager/secret|ssm/parameter|s3/object)/[^?#*]+$'
                  AND basis.source_object_ref='aws-content-scope:' || basis.scope_id::text)
          )
    ) rules ON true
), evaluated AS (
    SELECT matched.*,
       CASE WHEN content_type IN ('IAM_ACCESS_KEY_METADATA','AWS_SECRETS_MANAGER_METADATA','AWS_SSM_PARAMETER_METADATA','AWS_S3_BUCKET_METADATA') THEN 'METADATA_NOT_APPLICABLE'
            WHEN binding_id IS NULL THEN 'NO_ACTIVE_BINDING'
            WHEN NOT enabled OR response_origin='UNCLASSIFIED' THEN 'SCOPE_NOT_APPROVED'
            WHEN bound_revision<>revision OR bound_origin_version<>response_origin_version OR bound_fingerprint<>fingerprint THEN 'SCOPE_CHANGED'
            WHEN status<>'ACTIVE' THEN 'POLICY_RETIRED'
            WHEN now()<valid_from THEN 'POLICY_NOT_YET_VALID'
            WHEN valid_until IS NOT NULL AND now()>=valid_until THEN 'POLICY_EXPIRED'
            WHEN allow_count>0 AND deny_count>0 THEN 'POLICY_CONFLICT'
            WHEN allow_count>0 THEN 'EXPLICIT_ALLOW'
            WHEN deny_count>0 THEN 'EXPLICIT_DENY'
            ELSE 'NO_MATCHING_RULE' END AS reason_code
    FROM matched
)
SELECT occurrence_id,scope_id,binding_id,policy_id,policy_version,reason_code,
       CASE reason_code WHEN 'EXPLICIT_ALLOW' THEN 'ALLOWED' WHEN 'EXPLICIT_DENY' THEN 'DENIED' ELSE 'UNKNOWN' END::varchar(10) AS policy_result,
       (policy_recheck_required OR (exposure_status<>'UNKNOWN' AND (
           policy_assessed_binding_id IS DISTINCT FROM binding_id
           OR policy_assessed_origin_version IS DISTINCT FROM response_origin_version
           OR (binding_id IS NOT NULL AND reason_code NOT IN ('EXPLICIT_ALLOW','EXPLICIT_DENY'))
       ))) AS requires_reassessment
FROM evaluated;
