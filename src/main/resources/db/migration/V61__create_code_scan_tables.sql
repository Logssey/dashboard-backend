-- 코드 취약점(SAST) 결과 (security-solution-docs/code-security).
-- 서비스 레포의 code-scan 워크플로가 develop 에서 돌 때 도구별 SARIF 를 올린다.
-- 화면은 "지금 어떤 발견이 있는지"만 보여 주므로 레포·도구마다 마지막 검사만 남긴다 (새 검사가 오면 이전 것을 지운다).

CREATE TABLE code_scans (
    scan_id      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repository   VARCHAR(200) NOT NULL,
    tool         VARCHAR(20)  NOT NULL CHECK (tool IN ('semgrep', 'spotbugs')),
    commit_sha   CHAR(40)     NOT NULL,
    scanned_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    total        INTEGER      NOT NULL CHECK (total >= 0),
    UNIQUE (repository, tool)
);

CREATE TABLE code_findings (
    scan_id    BIGINT        NOT NULL REFERENCES code_scans (scan_id) ON DELETE CASCADE,
    seq        INTEGER       NOT NULL,
    rule_id    VARCHAR(300)  NOT NULL,
    severity   VARCHAR(10)   NOT NULL CHECK (severity IN ('HIGH', 'MEDIUM', 'LOW')),
    cwe        VARCHAR(20),
    message    VARCHAR(1000) NOT NULL,
    path       VARCHAR(500)  NOT NULL,
    line       INTEGER,
    help_uri   VARCHAR(500),
    PRIMARY KEY (scan_id, seq)
);
