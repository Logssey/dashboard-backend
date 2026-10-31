-- Versioned runtime rule catalog and generic evidence targets for process and file detections.

CREATE TABLE runtime_rules (
    rule_key VARCHAR(40) PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    version VARCHAR(40) NOT NULL,
    event_type VARCHAR(40) NOT NULL,
    target_type VARCHAR(20) NOT NULL CHECK (target_type IN ('PROCESS', 'FILE', 'NETWORK')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE runtime_rule_sensor_mappings (
    sensor_type VARCHAR(20) NOT NULL CHECK (sensor_type IN ('FALCO', 'TETRAGON')),
    source_rule VARCHAR(200) NOT NULL,
    rule_key VARCHAR(40) NOT NULL REFERENCES runtime_rules (rule_key) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (sensor_type, source_rule)
);
CREATE INDEX idx_runtime_rule_sensor_mappings_rule
    ON runtime_rule_sensor_mappings (rule_key);

INSERT INTO runtime_rules (rule_key, title, version, event_type, target_type) VALUES
    ('RUN-001', '컨테이너 셸 실행', '1.0.0', 'PROCESS_EXEC', 'PROCESS'),
    ('RUN-003', 'ServiceAccount 토큰 접근', '1.0.0', 'FILE_ACCESS', 'FILE'),
    ('RUN-004', '실행 중인 컨테이너의 패키지 관리자 실행', '1.0.0', 'PROCESS_EXEC', 'PROCESS'),
    ('RUN-007', '컨테이너 민감 경로 변경', '1.0.0', 'FILE_WRITE', 'FILE');

INSERT INTO runtime_rule_sensor_mappings (sensor_type, source_rule, rule_key) VALUES
    ('FALCO', 'Logssey RUN-001 Container Shell', 'RUN-001'),
    ('FALCO', 'Terminal shell in container', 'RUN-001'),
    ('FALCO', 'Logssey RUN-003 ServiceAccount Token Access', 'RUN-003'),
    ('FALCO', 'Logssey RUN-004 Package Manager Execution', 'RUN-004'),
    ('FALCO', 'Logssey RUN-007 Sensitive Path Write', 'RUN-007');

ALTER TABLE runtime_events
    ADD COLUMN target_type VARCHAR(20) CHECK (target_type IN ('PROCESS', 'FILE', 'NETWORK')),
    ADD COLUMN target_name VARCHAR(1000),
    ADD COLUMN operation VARCHAR(40);

ALTER TABLE runtime_findings
    ADD COLUMN target_type VARCHAR(20) CHECK (target_type IN ('PROCESS', 'FILE', 'NETWORK')),
    ADD COLUMN target_name VARCHAR(1000),
    ADD COLUMN operation VARCHAR(40);

UPDATE runtime_events
SET target_type = 'PROCESS', target_name = process_executable, operation = 'EXEC'
WHERE target_type IS NULL;

UPDATE runtime_findings
SET target_type = 'PROCESS', target_name = process_executable, operation = 'EXEC'
WHERE target_type IS NULL;

ALTER TABLE runtime_events
    ALTER COLUMN target_type SET NOT NULL,
    ALTER COLUMN target_name SET NOT NULL,
    ALTER COLUMN operation SET NOT NULL;

ALTER TABLE runtime_findings
    ALTER COLUMN target_type SET NOT NULL,
    ALTER COLUMN target_name SET NOT NULL,
    ALTER COLUMN operation SET NOT NULL;

CREATE INDEX idx_runtime_events_target ON runtime_events (target_type, target_name);
CREATE INDEX idx_runtime_findings_target ON runtime_findings (target_type, target_name);
