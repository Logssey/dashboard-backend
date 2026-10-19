-- IaC 보안 테이블 (설계: security-solution-docs/iac-security/03-architecture/database-schema.md)
-- 설계 초안과 다른 점: iac_run_path_changes 에 rule_id 를 둔다 (GET /prs/{n} 이 경로마다 규칙을 돌려줌).
-- 환경마다 다른 값(iac_repos, iac_data_assets)은 여기서 넣지 않는다.

CREATE TABLE iac_repos (
    repo_id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    full_name       VARCHAR(200) NOT NULL UNIQUE,
    default_branch  VARCHAR(100) NOT NULL,
    environment     VARCHAR(10)  NOT NULL CHECK (environment IN ('PROD', 'DEV')),
    enabled         BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE iac_rules (
    rule_id              VARCHAR(80) PRIMARY KEY,
    engine               VARCHAR(20) NOT NULL CHECK (engine IN ('CONFTEST', 'GIT', 'TERRAFORM', 'HASH', 'KICS', 'PATH', 'STATE', 'DRIFT')),
    default_enforcement  VARCHAR(10) NOT NULL CHECK (default_enforcement IN ('BLOCK', 'WARN', 'INFO', 'IGNORE')),
    default_severity     VARCHAR(10) CHECK (default_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    template_key         VARCHAR(80) NOT NULL,
    version              VARCHAR(40) NOT NULL,
    enabled              BOOLEAN     NOT NULL DEFAULT TRUE,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE iac_data_assets (
    data_asset_id  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    arn            VARCHAR(300) NOT NULL UNIQUE,
    kind           VARCHAR(20)  NOT NULL CHECK (kind IN ('RDS', 'SECRET', 'S3', 'TFSTATE')),
    tier           SMALLINT     NOT NULL CHECK (tier BETWEEN 1 AND 3),
    asset_id       BIGINT REFERENCES assets (asset_id) ON DELETE SET NULL,
    owner_team     VARCHAR(50),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE TABLE iac_runs (
    run_id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repo_id               BIGINT      NOT NULL REFERENCES iac_repos (repo_id),
    pr_number             INTEGER,
    head_sha              VARCHAR(40) NOT NULL,
    trigger_type          VARCHAR(10) NOT NULL CHECK (trigger_type IN ('PR', 'PUSH', 'MANUAL')),
    status                VARCHAR(20) NOT NULL CHECK (status IN ('QUEUED', 'GATE_FAILED', 'PLANNING', 'ANALYZING', 'DONE', 'ERROR', 'SUPERSEDED')),
    verdict               VARCHAR(10) CHECK (verdict IN ('BLOCK', 'WARN', 'INFO', 'PASS')),
    highest_severity      VARCHAR(10) CHECK (highest_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    graph_as_of           TIMESTAMPTZ,
    superseded_by_run_id  BIGINT REFERENCES iac_runs (run_id),
    requested_by_user_id  BIGINT REFERENCES dashboard_users (user_id),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at           TIMESTAMPTZ,
    CONSTRAINT ck_iac_runs_pr_number CHECK (trigger_type <> 'PR' OR pr_number IS NOT NULL)
);

CREATE INDEX idx_iac_runs_repo_pr ON iac_runs (repo_id, pr_number, created_at DESC);

CREATE TABLE iac_jobs (
    job_id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind                  VARCHAR(20) NOT NULL CHECK (kind IN ('ANALYZE_RUN', 'COLLECT_GRAPH', 'ENRICH_GRAPH', 'CHECK_DRIFT', 'CHECK_STATE')),
    trigger_type          VARCHAR(10) NOT NULL CHECK (trigger_type IN ('SCHEDULED', 'MANUAL', 'PR')),
    run_id                BIGINT REFERENCES iac_runs (run_id),
    requested_by_user_id  BIGINT REFERENCES dashboard_users (user_id),
    status                VARCHAR(20) NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'LEASED', 'SUCCEEDED', 'FAILED', 'CANCELLED')),
    attempt_no            INTEGER     NOT NULL DEFAULT 0,
    max_attempts          INTEGER     NOT NULL DEFAULT 3,
    available_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    lease_owner           VARCHAR(120),
    lease_until           TIMESTAMPTZ,
    stats                 JSONB,
    last_error_code       VARCHAR(80),
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at           TIMESTAMPTZ,
    CONSTRAINT ck_iac_jobs_analyze_run CHECK (kind <> 'ANALYZE_RUN' OR run_id IS NOT NULL),
    CONSTRAINT ck_iac_jobs_attempts CHECK (attempt_no >= 0 AND max_attempts > 0)
);

CREATE INDEX idx_iac_jobs_pending ON iac_jobs (available_at) WHERE status = 'PENDING';

CREATE TABLE iac_plan_payloads (
    run_id       BIGINT      PRIMARY KEY REFERENCES iac_runs (run_id) ON DELETE CASCADE,
    content      BYTEA       NOT NULL,
    size_bytes   INTEGER     NOT NULL CHECK (size_bytes <= 20971520),
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL
);

CREATE TABLE iac_findings (
    finding_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    rule_id           VARCHAR(80)  NOT NULL REFERENCES iac_rules (rule_id),
    source            VARCHAR(10)  NOT NULL CHECK (source IN ('GATE', 'RULE', 'PATH', 'STATE', 'DRIFT')),
    enforcement       VARCHAR(10)  NOT NULL CHECK (enforcement IN ('BLOCK', 'WARN', 'INFO', 'IGNORE')),
    severity          VARCHAR(10)  CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    environment       VARCHAR(10)  NOT NULL CHECK (environment IN ('PROD', 'DEV')),
    resource_address  VARCHAR(500),
    params            JSONB        NOT NULL DEFAULT '{}',
    fingerprint       VARCHAR(64)  NOT NULL UNIQUE,
    last_run_id       BIGINT REFERENCES iac_runs (run_id),
    last_job_id       BIGINT REFERENCES iac_jobs (job_id),
    status            VARCHAR(10)  NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'FIXED', 'ACCEPTED')),
    assignee_user_id  BIGINT REFERENCES dashboard_users (user_id),
    version           BIGINT       NOT NULL DEFAULT 0,
    first_seen_at     TIMESTAMPTZ  NOT NULL,
    last_seen_at      TIMESTAMPTZ  NOT NULL,
    CONSTRAINT ck_iac_findings_origin CHECK (last_run_id IS NOT NULL OR last_job_id IS NOT NULL)
);

CREATE INDEX idx_iac_findings_open ON iac_findings (status, severity);

CREATE TABLE iac_attack_paths (
    path_id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    fingerprint           VARCHAR(64)  NOT NULL UNIQUE,
    entry                 VARCHAR(200) NOT NULL,
    target_data_asset_id  BIGINT       NOT NULL REFERENCES iac_data_assets (data_asset_id),
    tier                  SMALLINT     NOT NULL CHECK (tier BETWEEN 1 AND 3),
    severity              VARCHAR(10)  NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    environment           VARCHAR(10)  NOT NULL CHECK (environment IN ('PROD', 'DEV')),
    hops                  JSONB        NOT NULL,
    length                SMALLINT     NOT NULL,
    status                VARCHAR(10)  NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN', 'CLOSED')),
    last_job_id           BIGINT REFERENCES iac_jobs (job_id),
    first_seen_at         TIMESTAMPTZ  NOT NULL,
    last_seen_at          TIMESTAMPTZ  NOT NULL
);

CREATE TABLE iac_run_path_changes (
    change_id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id            BIGINT      NOT NULL REFERENCES iac_runs (run_id) ON DELETE CASCADE,
    change            VARCHAR(10) NOT NULL CHECK (change IN ('ADDED', 'REMOVED', 'SHORTENED')),
    rule_id           VARCHAR(80) NOT NULL REFERENCES iac_rules (rule_id),
    path_id           BIGINT REFERENCES iac_attack_paths (path_id),
    path_fingerprint  VARCHAR(64) NOT NULL,
    tier              SMALLINT    NOT NULL CHECK (tier BETWEEN 1 AND 3),
    severity          VARCHAR(10) CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    hops              JSONB       NOT NULL,
    cause_address     VARCHAR(500),
    evidence          JSONB,
    CONSTRAINT uq_iac_run_path_change UNIQUE (run_id, path_fingerprint),
    CONSTRAINT ck_iac_run_path_changes_added CHECK (change <> 'ADDED' OR path_id IS NULL)
);

-- 추가만 한다. UPDATE·DELETE 를 막는 것은 DB 계정 권한으로 한다 (설계 DB 계정 절).
CREATE TABLE iac_audit_events (
    audit_id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_kind     VARCHAR(10) NOT NULL CHECK (actor_kind IN ('USER', 'CI', 'WORKER', 'SYSTEM')),
    actor_user_id  BIGINT REFERENCES dashboard_users (user_id),
    entity_type    VARCHAR(30) NOT NULL,
    entity_id      BIGINT      NOT NULL,
    event_type     VARCHAR(50) NOT NULL,
    before_safe    JSONB,
    after_safe     JSONB,
    occurred_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT ck_iac_audit_events_user CHECK (actor_kind <> 'USER' OR actor_user_id IS NOT NULL)
);

-- 규칙 (rule-spec.md). ② gate 규칙은 infrastructure 의 policy/rules.json 과 같게 유지한다.
-- 템플릿 키는 규칙 ID 와 같게 둔다. 바꿀 때는 새 마이그레이션으로 한다.
INSERT INTO iac_rules (rule_id, engine, default_enforcement, default_severity, template_key, version) VALUES
    ('gate.exec_data_source',       'CONFTEST',  'BLOCK', 'CRITICAL', 'gate.exec_data_source',       '1'),
    ('gate.provisioner',            'CONFTEST',  'BLOCK', 'CRITICAL', 'gate.provisioner',            '1'),
    ('gate.lambda_invocation',      'CONFTEST',  'BLOCK', 'HIGH',     'gate.lambda_invocation',      '1'),
    ('gate.provider_not_allowed',   'CONFTEST',  'BLOCK', 'HIGH',     'gate.provider_not_allowed',   '1'),
    ('gate.provider_unpinned',      'CONFTEST',  'WARN',  'MEDIUM',   'gate.provider_unpinned',      '1'),
    ('gate.module_unpinned',        'CONFTEST',  'WARN',  'MEDIUM',   'gate.module_unpinned',        '1'),
    ('gate.backend_changed',        'GIT',       'BLOCK', 'HIGH',     'gate.backend_changed',        '1'),
    ('gate.lock_changed',           'GIT',       'WARN',  'MEDIUM',   'gate.lock_changed',           '1'),
    ('gate.workflow_changed',       'GIT',       'WARN',  'HIGH',     'gate.workflow_changed',       '1'),
    ('gate.lock_mismatch',          'TERRAFORM', 'BLOCK', 'HIGH',     'gate.lock_mismatch',          '1'),
    ('gate.module_content_changed', 'HASH',      'WARN',  'HIGH',     'gate.module_content_changed', '1'),
    ('gate.unscanned_file',         'GIT',       'BLOCK', 'HIGH',     'gate.unscanned_file',         '1'),
    ('gate.plan_failed',            'TERRAFORM', 'BLOCK', NULL,       'gate.plan_failed',            '1'),
    ('path.tier1.added',            'PATH',      'BLOCK', 'CRITICAL', 'path.tier1.added',            '1'),
    ('path.tier1.reach_only',       'PATH',      'WARN',  'HIGH',     'path.tier1.reach_only',       '1'),
    ('path.tier2.added',            'PATH',      'WARN',  'HIGH',     'path.tier2.added',            '1'),
    ('path.shortened',              'PATH',      'WARN',  'MEDIUM',   'path.shortened',              '1'),
    ('path.imds_v1_added',          'PATH',      'WARN',  'MEDIUM',   'path.imds_v1_added',          '1'),
    ('path.removed',                'PATH',      'INFO',  NULL,       'path.removed',                '1'),
    ('state.reader_increase',       'STATE',     'WARN',  'HIGH',     'state.reader_increase',       '1');
