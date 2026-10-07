-- Logssey 대시보드 테이블 (설계: 04-data/schema-and-erd.md)

-- 1. 대시보드 사용자
CREATE TABLE dashboard_users (
    user_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    login_id       VARCHAR(50)  NOT NULL UNIQUE,
    password_hash  VARCHAR(255) NOT NULL,
    display_name   VARCHAR(50)  NOT NULL,
    role           VARCHAR(10)  NOT NULL DEFAULT 'ADMIN' CHECK (role IN ('ADMIN')),
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_login_at  TIMESTAMPTZ
);

-- 2. 자산
CREATE TABLE assets (
    asset_id     BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name         VARCHAR(200) NOT NULL,
    provider     VARCHAR(20)  NOT NULL CHECK (provider IN ('AWS', 'KUBERNETES', 'GITHUB')),
    asset_type   VARCHAR(50)  NOT NULL,
    environment  VARCHAR(10)  NOT NULL CHECK (environment IN ('PROD', 'DEV')),
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT uq_assets_provider_name_env UNIQUE (provider, name, environment)
);

-- 3. 탐지 이벤트
--    자산 연결은 선택(asset_id NULL 허용), 환경은 필수.
--    자산이 있으면 이벤트 환경 = 자산 환경 이어야 하며, 이 검사는 백엔드가 저장 시 한다 (ADR/ERD 결정)
CREATE TABLE detection_events (
    event_id        BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    asset_id        BIGINT REFERENCES assets (asset_id) ON DELETE RESTRICT,
    display_id      VARCHAR(20),
    severity        VARCHAR(10)  NOT NULL CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    title           VARCHAR(200) NOT NULL,
    environment     VARCHAR(10)  NOT NULL CHECK (environment IN ('PROD', 'DEV')),
    owner_team      VARCHAR(50)  NOT NULL,
    review_status   VARCHAR(20)  NOT NULL DEFAULT 'UNREVIEWED' CHECK (review_status IN ('UNREVIEWED', 'REVIEWED')),
    action_status   VARCHAR(20)  NOT NULL DEFAULT 'OPEN' CHECK (action_status IN ('OPEN', 'IN_PROGRESS', 'RESOLVED', 'RISK_ACCEPTED')),
    detected_at     TIMESTAMPTZ  NOT NULL,
    domain          VARCHAR(20)  CHECK (domain IN ('SECRETS', 'CONFIGURATION', 'IDENTITIES', 'RUNTIME', 'VULNERABILITIES')),
    evidence        TEXT,
    recommendation  TEXT,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ
);

-- 조회 속도용 인덱스: 위험 추이 / 미검토·우선 확인 목록
CREATE INDEX idx_detection_events_detected_at ON detection_events (detected_at);
CREATE INDEX idx_detection_events_review_severity ON detection_events (review_status, severity);
