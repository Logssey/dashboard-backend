-- Reach Finding의 CVSS v3 기본 점수 (통합 현황 보안 점수, dashboard-design-docs ADR-D012 "이미지 등급")
-- 스캐너 심각도를 정한 출처(Trivy SeveritySource, 없으면 NVD → GHSA)의 점수를 그대로 둔다. 등급 구간 안에서 감점을 정하는 데 쓴다.
-- 이 칸이 생기기 전에 올린 묶음과 CVSS가 없는 취약점은 NULL이다
ALTER TABLE reach_findings
    ADD COLUMN cvss_score  NUMERIC(3, 1),
    ADD COLUMN cvss_source VARCHAR(40),
    ADD CONSTRAINT ck_reach_findings_cvss CHECK (cvss_score IS NULL OR cvss_score BETWEEN 0 AND 10);
