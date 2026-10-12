-- 키(자격 증명) 관리 테이블 — 샘플 단계 (설계: dashboard-design-docs 04-data/credentials-draft.md)
-- 키 원문은 저장하지 않는다 (ADR-D009). 실제 키 정보는 ADR-D005 결정 후에만 넣는다.
-- 이 파일은 GitHub에 올린 뒤 고치지 않는다. 바꿀 내용은 V3 파일을 새로 추가한다.
-- assets는 이번 단계에서 바꾸지 않는다. Notion 키는 asset_id를 비운다 (ERD 초안 열린 질문 7).

-- 1. 키
CREATE TABLE credentials (
    credential_id      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    issuer             VARCHAR(20)  NOT NULL CHECK (issuer IN ('AWS', 'GITHUB', 'NOTION')),
    credential_type    VARCHAR(50)  NOT NULL,
    classification     VARCHAR(20)  NOT NULL CHECK (classification IN ('SECRET', 'RESTRICTED_PUBLIC', 'MANAGED_KEY')),
    display_name       VARCHAR(200),
    external_id        VARCHAR(200),
    masked_value       VARCHAR(50),
    fingerprint        VARCHAR(100),
    owner              VARCHAR(100),
    owner_team         VARCHAR(50),
    purpose            VARCHAR(200),
    scope              TEXT,
    environment        VARCHAR(10)  CHECK (environment IN ('PROD', 'DEV')),
    asset_id           BIGINT REFERENCES assets (asset_id) ON DELETE RESTRICT,
    storage_location   VARCHAR(300),
    status             VARCHAR(20)  NOT NULL DEFAULT 'UNKNOWN'
                           CHECK (status IN ('ACTIVE', 'INACTIVE', 'EXPIRED', 'REVOKED', 'UNKNOWN')),
    source             VARCHAR(10)  NOT NULL CHECK (source IN ('API', 'SCAN', 'MANUAL')),
    issued_at          TIMESTAMPTZ,
    expiry_policy      VARCHAR(10)  NOT NULL DEFAULT 'UNKNOWN' CHECK (expiry_policy IN ('FIXED', 'NEVER', 'UNKNOWN')),
    expires_at         TIMESTAMPTZ,
    last_used_at       TIMESTAMPTZ,
    last_collected_at  TIMESTAMPTZ,
    rotation_method    TEXT,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ,
    -- 만료 방식이 FIXED면 만료 시각이 있어야 한다
    CONSTRAINT ck_credentials_fixed_expiry CHECK (expiry_policy <> 'FIXED' OR expires_at IS NOT NULL)
);

-- 같은 키를 두 번 수집하지 않는다 (플랫폼 쪽 ID가 있을 때만)
CREATE UNIQUE INDEX uq_credentials_issuer_external_id ON credentials (issuer, external_id) WHERE external_id IS NOT NULL;
-- 같은 유출 키를 두 번 등록하지 않는다 (지문이 있을 때만)
CREATE UNIQUE INDEX uq_credentials_fingerprint ON credentials (fingerprint) WHERE fingerprint IS NOT NULL;

-- 2. 탐지 이벤트에 관련 키 연결 (키와 상관없는 탐지는 비운다)
ALTER TABLE detection_events
    ADD COLUMN credential_id BIGINT REFERENCES credentials (credential_id) ON DELETE RESTRICT;

CREATE INDEX idx_detection_events_credential_id ON detection_events (credential_id);
