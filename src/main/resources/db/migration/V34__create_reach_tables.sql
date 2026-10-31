-- 취약점 관리(Reach) 테이블 (설계: security-solution-docs/reachability-analysis/03-architecture/database-schema.md)
-- Finding은 (대상, purl, 취약점 ID)마다 한 행으로 갱신하고, 판정은 스캔마다 새 행으로 쌓는다 (설계 2절)
-- 결과 데이터와 다음 단계 테이블(reach_sboms, reach_workloads, reach_ci_checks)은 여기서 넣지 않는다

-- 이미지는 태그가 아니라 digest로 구분한다 (ECR 태그는 덮어쓸 수 있음)
CREATE TABLE reach_targets (
    target_id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    target_type       VARCHAR(10)  NOT NULL CHECK (target_type IN ('REPO', 'IMAGE')),
    app               VARCHAR(10)  NOT NULL CHECK (app IN ('API', 'WEB', 'CHAT')),
    repo_name         VARCHAR(200),
    repo_path         VARCHAR(200),
    repo_commit       VARCHAR(64),
    image_repository  VARCHAR(200),
    image_digest      VARCHAR(80),
    image_revision    VARCHAR(64),
    image_created_at  TIMESTAMPTZ,
    source_tree       VARCHAR(64),
    display_name      VARCHAR(200) NOT NULL,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT ck_reach_targets_repo CHECK (target_type <> 'REPO' OR (repo_name IS NOT NULL AND repo_commit IS NOT NULL)),
    CONSTRAINT ck_reach_targets_image CHECK (target_type <> 'IMAGE' OR (image_repository IS NOT NULL AND image_digest IS NOT NULL))
);

CREATE UNIQUE INDEX uq_reach_targets_image ON reach_targets (image_repository, image_digest)
    WHERE target_type = 'IMAGE';
CREATE UNIQUE INDEX uq_reach_targets_repo ON reach_targets (repo_name, COALESCE(repo_path, ''), repo_commit)
    WHERE target_type = 'REPO';

CREATE TABLE reach_scans (
    scan_id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    target_id                BIGINT       NOT NULL REFERENCES reach_targets (target_id),
    scan_status              VARCHAR(10)  NOT NULL DEFAULT 'QUEUED' CHECK (scan_status IN ('QUEUED', 'RUNNING', 'SUCCEEDED', 'FAILED')),
    trigger_type             VARCHAR(15)  NOT NULL CHECK (trigger_type IN ('MANUAL', 'PR', 'IMAGE_BUILD', 'SCHEDULE')),
    rescan_of_scan_id        BIGINT REFERENCES reach_scans (scan_id),
    requested_by_kind        VARCHAR(10)  NOT NULL CHECK (requested_by_kind IN ('USER', 'CI', 'SYSTEM')),
    requested_by_user_id     BIGINT REFERENCES dashboard_users (user_id),
    requested_by_repository  VARCHAR(200),
    requested_by_subject     VARCHAR(300),
    tools                    JSONB        NOT NULL DEFAULT '{}',
    analysis                 JSONB,
    stages                   JSONB        NOT NULL DEFAULT '[]',
    failure_code             VARCHAR(80),
    failure_stage            VARCHAR(10)  CHECK (failure_stage IN ('SBOM', 'MATCH', 'L1', 'L2', 'REPORT')),
    failure_message          VARCHAR(500),
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT now(),
    started_at               TIMESTAMPTZ,
    finished_at              TIMESTAMPTZ,
    CONSTRAINT ck_reach_scans_requester CHECK (
        (requested_by_kind = 'USER' AND requested_by_user_id IS NOT NULL)
        OR (requested_by_kind = 'CI' AND requested_by_repository IS NOT NULL AND requested_by_subject IS NOT NULL)
        OR requested_by_kind = 'SYSTEM'),
    CONSTRAINT ck_reach_scans_failure CHECK (scan_status <> 'FAILED' OR failure_code IS NOT NULL),
    CONSTRAINT ck_reach_scans_finished CHECK ((scan_status IN ('SUCCEEDED', 'FAILED')) = (finished_at IS NOT NULL))
);

CREATE INDEX idx_reach_scans_target_latest ON reach_scans (target_id, scan_status, finished_at DESC, scan_id DESC);

CREATE TABLE reach_findings (
    finding_id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    target_id           BIGINT       NOT NULL REFERENCES reach_targets (target_id),
    purl                VARCHAR(500) NOT NULL,
    component_name      VARCHAR(200) NOT NULL,
    component_version   VARCHAR(100) NOT NULL,
    ecosystem           VARCHAR(20)  NOT NULL,
    component_path      VARCHAR(500),
    vulnerability_id    VARCHAR(40)  NOT NULL,
    severity            VARCHAR(10)  NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN')),
    severity_note       VARCHAR(500),
    vuln_title          VARCHAR(500),
    vuln_description    TEXT,
    affected_feature    VARCHAR(500),
    fixed_versions      TEXT[]       NOT NULL DEFAULT '{}',
    cwe_ids             TEXT[]       NOT NULL DEFAULT '{}',
    reference_urls      TEXT[]       NOT NULL DEFAULT '{}',
    sources             TEXT[]       NOT NULL CHECK (cardinality(sources) > 0 AND sources <@ ARRAY['TRIVY', 'GRYPE']::TEXT[]),
    deployment          VARCHAR(15)  NOT NULL DEFAULT 'UNKNOWN' CHECK (deployment IN ('RUNNING', 'NOT_RUNNING', 'UNKNOWN')),
    upgrade             JSONB,
    last_scan_id        BIGINT       NOT NULL REFERENCES reach_scans (scan_id),
    first_seen_at       TIMESTAMPTZ  NOT NULL,
    last_seen_at        TIMESTAMPTZ  NOT NULL,
    CONSTRAINT uq_reach_findings_identity UNIQUE (target_id, purl, vulnerability_id),
    CONSTRAINT ck_reach_findings_seen CHECK (first_seen_at <= last_seen_at)
);

CREATE INDEX idx_reach_findings_last_scan ON reach_findings (last_scan_id);
CREATE INDEX idx_reach_findings_carry_key ON reach_findings (purl, vulnerability_id);

-- 스캔마다 새 행. is_current 인 행이 지금 판정이다.
CREATE TABLE reach_verdicts (
    verdict_id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    finding_id           BIGINT       NOT NULL REFERENCES reach_findings (finding_id),
    scan_id              BIGINT       NOT NULL REFERENCES reach_scans (scan_id),
    status               VARCHAR(15)  NOT NULL CHECK (status IN ('REACHABLE', 'UNREACHABLE', 'UNKNOWN', 'NOT_ANALYZED')),
    method               VARCHAR(10)  CHECK (method IN ('CALLGRAPH', 'RULE', 'MANUAL')),
    not_analyzed_reason  VARCHAR(30)  CHECK (not_analyzed_reason IN ('NO_VULN_FUNCTION_DATA', 'OS_PACKAGE', 'UNANALYZED_COPY', 'UNSUPPORTED_ECOSYSTEM', 'ANALYSIS_TIMEOUT')),
    summary              VARCHAR(500) NOT NULL,
    rule_id              VARCHAR(80),
    vuln_function_ids    INTEGER[]    NOT NULL DEFAULT '{}',
    callgraph            JSONB,
    engine               JSONB,
    evidence_hash        VARCHAR(64),
    is_current           BOOLEAN      NOT NULL DEFAULT FALSE,
    analyzed_at          TIMESTAMPTZ  NOT NULL,
    created_by_user_id   BIGINT REFERENCES dashboard_users (user_id),
    CONSTRAINT ck_reach_verdicts_method CHECK ((status = 'NOT_ANALYZED') = (method IS NULL)),
    CONSTRAINT ck_reach_verdicts_reason CHECK ((status = 'NOT_ANALYZED') = (not_analyzed_reason IS NOT NULL)),
    CONSTRAINT ck_reach_verdicts_manual CHECK ((COALESCE(method, '') = 'MANUAL') = (created_by_user_id IS NOT NULL)),
    CONSTRAINT ck_reach_verdicts_tool CHECK (COALESCE(method, '') = 'MANUAL' OR (engine IS NOT NULL AND evidence_hash IS NOT NULL))
);

CREATE UNIQUE INDEX uq_reach_verdicts_tool ON reach_verdicts (finding_id, scan_id)
    WHERE method IS DISTINCT FROM 'MANUAL';
CREATE UNIQUE INDEX uq_reach_verdicts_current ON reach_verdicts (finding_id)
    WHERE is_current;
CREATE INDEX idx_reach_verdicts_scan ON reach_verdicts (scan_id, status);

CREATE TABLE reach_evidence (
    evidence_id    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    verdict_id     BIGINT        NOT NULL REFERENCES reach_verdicts (verdict_id),
    ord            SMALLINT      NOT NULL CHECK (ord > 0),
    kind           VARCHAR(10)   NOT NULL CHECK (kind IN ('FACT', 'PATH', 'RULE', 'NOTE', 'RUNTIME')),
    summary        VARCHAR(1000) NOT NULL,
    fact_id        VARCHAR(120),
    rule_id        VARCHAR(80),
    informational  BOOLEAN       NOT NULL DEFAULT FALSE,
    detail         JSONB         NOT NULL DEFAULT '{}',
    CONSTRAINT uq_reach_evidence_order UNIQUE (verdict_id, ord),
    CONSTRAINT ck_reach_evidence_fact CHECK (kind <> 'FACT' OR fact_id IS NOT NULL),
    CONSTRAINT ck_reach_evidence_rule CHECK (kind <> 'RULE' OR rule_id IS NOT NULL)
);

-- Finding마다 현재 검토 한 행. 바뀔 때마다 reach_review_history 에 같은 트랜잭션으로 한 행을 추가한다.
CREATE TABLE reach_reviews (
    finding_id               BIGINT        PRIMARY KEY REFERENCES reach_findings (finding_id),
    review_state             VARCHAR(15)   NOT NULL DEFAULT 'UNREVIEWED' CHECK (review_state IN ('UNREVIEWED', 'PROVISIONAL', 'CONFIRMED')),
    status                   VARCHAR(15)   CHECK (status IN ('REACHABLE', 'UNREACHABLE', 'UNKNOWN')),
    note                     VARCHAR(2000),
    proposal                 JSONB,
    reviewer_user_id         BIGINT REFERENCES dashboard_users (user_id),
    reviewed_at              TIMESTAMPTZ,
    version                  INTEGER       NOT NULL DEFAULT 1 CHECK (version > 0),
    base_verdict_id          BIGINT REFERENCES reach_verdicts (verdict_id),
    carried_from_finding_id  BIGINT REFERENCES reach_findings (finding_id),
    carried_from_scan_id     BIGINT REFERENCES reach_scans (scan_id),
    reset_reason             VARCHAR(20)   CHECK (reset_reason IN ('VERDICT_CHANGED', 'EVIDENCE_CHANGED')),
    updated_at               TIMESTAMPTZ   NOT NULL DEFAULT now(),
    CONSTRAINT ck_reach_reviews_human CHECK (
        review_state = 'UNREVIEWED'
        OR (status IS NOT NULL AND note IS NOT NULL AND reviewer_user_id IS NOT NULL AND reviewed_at IS NOT NULL)),
    CONSTRAINT ck_reach_reviews_proposal CHECK (proposal IS NULL OR review_state = 'UNREVIEWED'),
    CONSTRAINT ck_reach_reviews_reset CHECK (reset_reason IS NULL OR review_state = 'UNREVIEWED'),
    CONSTRAINT ck_reach_reviews_carried CHECK ((carried_from_finding_id IS NULL) = (carried_from_scan_id IS NULL))
);

CREATE TABLE reach_review_history (
    history_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    finding_id        BIGINT        NOT NULL REFERENCES reach_findings (finding_id),
    version           INTEGER       NOT NULL CHECK (version > 0),
    review_state      VARCHAR(15)   NOT NULL CHECK (review_state IN ('UNREVIEWED', 'PROVISIONAL', 'CONFIRMED')),
    status            VARCHAR(15)   CHECK (status IN ('REACHABLE', 'UNREACHABLE', 'UNKNOWN')),
    note              VARCHAR(2000),
    proposal          JSONB,
    reviewer_user_id  BIGINT REFERENCES dashboard_users (user_id),
    reviewed_at       TIMESTAMPTZ,
    change_kind       VARCHAR(10)   NOT NULL CHECK (change_kind IN ('HUMAN', 'CARRIED', 'RESET')),
    recorded_at       TIMESTAMPTZ   NOT NULL DEFAULT now(),
    CONSTRAINT uq_reach_review_history_version UNIQUE (finding_id, version)
);
