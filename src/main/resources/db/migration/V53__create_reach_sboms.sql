-- Reach SBOM 보관 (PRD FR-02, ARD C-13·Q-06, DB 스키마 3-3 reach_sboms)
-- 결과 업로드(API-13)의 CycloneDX JSON을 스캔마다 gzip으로 둔다. 하루 1번 재대조(FR-11, API-01·12 rescanOf)의 입력이다.
-- 서비스 SBOM은 gzip 약 15KB라 DB에 둔다(덤프·스냅숏에 함께 들어간다). 보관 기간은 아직 두지 않는다
CREATE TABLE reach_sboms (
    scan_id          BIGINT       PRIMARY KEY REFERENCES reach_scans (scan_id),
    format           VARCHAR(20)  NOT NULL DEFAULT 'CYCLONEDX_JSON' CHECK (format IN ('CYCLONEDX_JSON')),
    content_gzip     BYTEA        NOT NULL,
    content_sha256   VARCHAR(64)  NOT NULL,
    component_count  INTEGER      NOT NULL CHECK (component_count >= 0),
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT now()
);
