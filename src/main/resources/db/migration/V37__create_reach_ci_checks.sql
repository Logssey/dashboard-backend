-- Reach CI 검사 (설계: security-solution-docs/reachability-analysis/03-architecture/database-schema.md 3-3)
-- 검사 하나가 스캔 하나를 만든다. API-12(CI 검사), API-13(결과 업로드), API-01(수동 스캔, mode = MANUAL)이 같이 쓴다
-- 게이트 결과는 저장하지 않는다. 스캔의 판정과 기준 스캔의 판정은 바뀌지 않아서 결과 조회 때 계산해도 값이 같다

CREATE TABLE reach_ci_checks (
    check_id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    scan_id              BIGINT       NOT NULL REFERENCES reach_scans (scan_id),
    mode                 VARCHAR(15)  NOT NULL CHECK (mode IN ('PR', 'IMAGE_BUILD', 'SCHEDULE', 'MANUAL')),
    repository           VARCHAR(200),
    head_commit          VARCHAR(64),
    pr_number            INTEGER      CHECK (pr_number > 0),
    pr_base_ref          VARCHAR(255),
    pr_head_ref          VARCHAR(255),
    policy               VARCHAR(15)  NOT NULL DEFAULT 'REPORT_ONLY' CHECK (policy IN ('REPORT_ONLY', 'GATE')),
    baseline_scan_id     BIGINT REFERENCES reach_scans (scan_id),
    -- API-01의 options(crossCheck, l1, l2). 러너가 읽는다
    options              JSONB        NOT NULL DEFAULT '{}',
    -- 멱등 키는 호출 주체별이다 (API 명세 2-7). scope는 USER:<user_id>, OIDC를 붙이면 CI:<repository>
    idempotency_scope    VARCHAR(220) NOT NULL,
    idempotency_key      VARCHAR(64)  NOT NULL,
    request_hash         VARCHAR(64)  NOT NULL,
    results_uploaded_at  TIMESTAMPTZ,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_reach_ci_checks_scan UNIQUE (scan_id),
    CONSTRAINT uq_reach_ci_checks_idempotency UNIQUE (idempotency_scope, idempotency_key),
    -- 수동 실행(API-01)의 이미지 대상은 레포를 모른다 (서비스 등록 목록 PRD FR-15 전)
    CONSTRAINT ck_reach_ci_checks_repository CHECK (mode = 'MANUAL' OR repository IS NOT NULL),
    CONSTRAINT ck_reach_ci_checks_pr CHECK (mode <> 'PR' OR head_commit IS NOT NULL)
);
