-- Reach L3 능동 관측 결과 (PRD FR-14, US-12 "L2 판정과 나란히 본다")
-- L3는 판정 옆에 놓는 근거다. 판정(reach_verdicts)·근거(reach_evidence)·검토와 따로 둬서 상태·근거 해시·게이트를 바꾸지 않는다.
-- 근거 해시에 넣으면 앱을 띄우지 않는 재대조(SCHEDULE)마다 근거가 달라져 사람 검토가 되돌아간다

-- L3 실행 한 번. 스캔마다 많아야 하나 (러너가 앱을 띄운 스캔만). FAILED면 러너가 남긴 사유만 있다
CREATE TABLE reach_l3_runs (
    scan_id             BIGINT       PRIMARY KEY REFERENCES reach_scans (scan_id),
    run_status          VARCHAR(10)  NOT NULL CHECK (run_status IN ('SUCCEEDED', 'FAILED')),
    error               VARCHAR(500),
    scenario            VARCHAR(64),
    observation_method  VARCHAR(10)  CHECK (observation_method IN ('COVERAGE', 'MAPS', 'UPROBE')),
    observed_at         TIMESTAMPTZ,
    -- 도달 수준별 CVE 수 (러너 집계 그대로)
    counts              JSONB        NOT NULL DEFAULT '{}',
    -- FR-14 근거 항목: build(imageDigest), configKeys(이름·켜짐 여부, 값 없음), invocations(보낸 요청), scope, 도구 버전
    detail              JSONB        NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT ck_reach_l3_runs_failed CHECK (run_status <> 'FAILED' OR error IS NOT NULL),
    CONSTRAINT ck_reach_l3_runs_succeeded CHECK (run_status <> 'SUCCEEDED' OR (scenario IS NOT NULL AND observed_at IS NOT NULL))
);

-- Finding의 지금 L3 결과. Finding은 대상(이미지 digest)마다라, 같은 이미지의 새 실행이 덮어쓴다(이력은 스캔 아티팩트).
-- 앱을 띄우지 않은 스캔(재대조, PR)은 건드리지 않아 그 이미지의 마지막 결과가 남는다
CREATE TABLE reach_l3_results (
    finding_id       BIGINT       PRIMARY KEY REFERENCES reach_findings (finding_id),
    scan_id          BIGINT       NOT NULL REFERENCES reach_l3_runs (scan_id),
    -- REGION 취약 구간 실행 / FUNCTION 취약 함수까지 / NONE 모두 확인했고 실행 없음 / NOT_RECORDED 확인 못 한 것이 있음
    reached          VARCHAR(15)  NOT NULL CHECK (reached IN ('REGION', 'FUNCTION', 'NONE', 'NOT_RECORDED')),
    -- FUNCTION일 때: true면 구간을 봤고 미실행, false면 구간을 확인하지 못함
    regions_checked  BOOLEAN      NOT NULL,
    -- 앱이 뜨는 동안에만 실행됨 (요청으로 실행된 것과 구분)
    startup_only     BOOLEAN      NOT NULL DEFAULT false,
    -- during(구간 id), functions, regions, paths, note, installedVersions, regionVersion (러너 l3.py 출력 이름 그대로)
    detail           JSONB        NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_reach_l3_results_scan ON reach_l3_results (scan_id);
