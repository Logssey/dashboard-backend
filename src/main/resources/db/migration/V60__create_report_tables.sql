-- 보안 파트 리포트 (양식: "보안 기능 통합 리포트 양식" 문서)
-- 리포트 하나는 파트 하나(IAC·SECRET·VULNERABILITY·RUNTIME)의 스냅샷이다.
-- 만든 시각의 값을 고정해 content 에 저장하므로 다시 열어도 같은 숫자가 나온다.
-- 삭제는 목록에서 숨기는 것이다: 본문과 건별 AI 대응 방법은 지우고, 누가 언제 지웠는지와 생성·열람 기록은 남긴다.

CREATE TABLE report_snapshots (
    report_id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    part            VARCHAR(20)  NOT NULL CHECK (part IN ('IAC', 'SECRET', 'VULNERABILITY', 'RUNTIME')),
    name            VARCHAR(120) NOT NULL,
    period_from     DATE         NOT NULL,
    period_to       DATE         NOT NULL,
    content         JSONB        NOT NULL,
    schema_version  SMALLINT     NOT NULL DEFAULT 1,
    created_by      BIGINT       NOT NULL REFERENCES dashboard_users (user_id),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    deleted_by      BIGINT       REFERENCES dashboard_users (user_id),
    deleted_at      TIMESTAMPTZ,
    CHECK (period_from <= period_to),
    CHECK ((deleted_at IS NULL) = (deleted_by IS NULL))
);

CREATE INDEX idx_report_snapshots_created_at ON report_snapshots (created_at DESC) WHERE deleted_at IS NULL;

-- 취약점 한 건에 대해 AI 가 만든 대응 방법. 처음 만든 결과를 리포트에 붙여 두고 다시 부르지 않는다
CREATE TABLE report_finding_advice (
    report_id   BIGINT       NOT NULL REFERENCES report_snapshots (report_id),
    finding_id  VARCHAR(40)  NOT NULL,
    content     JSONB        NOT NULL,
    created_by  BIGINT       NOT NULL REFERENCES dashboard_users (user_id),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (report_id, finding_id)
);

-- 생성·열람·인쇄·삭제 기록 (양식의 "열람·감사" 규칙)
CREATE TABLE report_audit_events (
    event_id    BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    report_id   BIGINT       NOT NULL REFERENCES report_snapshots (report_id),
    user_id     BIGINT       NOT NULL REFERENCES dashboard_users (user_id),
    event_type  VARCHAR(10)  NOT NULL CHECK (event_type IN ('CREATED', 'VIEWED', 'PRINTED', 'DELETED')),
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX idx_report_audit_events_report ON report_audit_events (report_id, created_at DESC);
