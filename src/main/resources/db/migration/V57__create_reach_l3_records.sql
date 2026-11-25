-- Reach L3 실행 기록 보관 (PRD FR-14, FR-11 재대조)
-- 러너가 이미지를 띄워 남긴 실행 기록(JaCoCo 실행 데이터, 구간마다 1개 + run.json)을 tar.xz 그대로 둔다.
-- 하루 1번 재대조가 앱을 다시 띄우지 않고 이 기록을 오늘의 판정 데이터·취약점 목록과 다시 대조한다(새 CVE까지).
-- Re:Used api 기준 한 벌이 약 0.3MB. 앱마다 최근 이미지 몇 개와 실행 중인 이미지의 것만 남긴다(적재할 때 정리)
CREATE TABLE reach_l3_records (
    scan_id         BIGINT       PRIMARY KEY REFERENCES reach_l3_runs (scan_id),
    format          VARCHAR(10)  NOT NULL DEFAULT 'TAR_XZ' CHECK (format IN ('TAR_XZ')),
    content         BYTEA        NOT NULL,
    content_sha256  VARCHAR(64)  NOT NULL,
    byte_size       INTEGER      NOT NULL CHECK (byte_size > 0),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);
