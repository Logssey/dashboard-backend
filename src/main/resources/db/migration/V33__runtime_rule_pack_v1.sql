-- Runtime rule pack v1: explicit lifecycle, rule metadata and observe-only event handling.

ALTER TABLE runtime_rules
    DROP CONSTRAINT runtime_rules_target_type_check;
ALTER TABLE runtime_rules
    ADD CONSTRAINT runtime_rules_target_type_check
        CHECK (target_type IN ('PROCESS', 'FILE', 'NETWORK', 'CONTAINER'));

ALTER TABLE runtime_events
    DROP CONSTRAINT runtime_events_target_type_check;
ALTER TABLE runtime_events
    ADD CONSTRAINT runtime_events_target_type_check
        CHECK (target_type IN ('PROCESS', 'FILE', 'NETWORK', 'CONTAINER'));

ALTER TABLE runtime_findings
    DROP CONSTRAINT runtime_findings_target_type_check;
ALTER TABLE runtime_findings
    ADD CONSTRAINT runtime_findings_target_type_check
        CHECK (target_type IN ('PROCESS', 'FILE', 'NETWORK', 'CONTAINER'));

ALTER TABLE runtime_rules
    ADD COLUMN pack_version VARCHAR(40) NOT NULL DEFAULT '1.0.0',
    ADD COLUMN mode VARCHAR(20) NOT NULL DEFAULT 'DETECT'
        CHECK (mode IN ('DETECT', 'OBSERVE', 'DRAFT')),
    ADD COLUMN maturity VARCHAR(20) NOT NULL DEFAULT 'STABLE'
        CHECK (maturity IN ('STABLE', 'INCUBATING', 'EXPERIMENTAL')),
    ADD COLUMN operation VARCHAR(40),
    ADD COLUMN sensors JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN mitre_techniques JSONB NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN noise_budget_per_minute INTEGER NOT NULL DEFAULT 300
        CHECK (noise_budget_per_minute > 0),
    ADD COLUMN owner VARCHAR(120) NOT NULL DEFAULT 'Runtime Security';

INSERT INTO runtime_rules
    (rule_key, title, version, event_type, target_type, operation, mode, maturity,
     sensors, mitre_techniques, noise_budget_per_minute, owner)
VALUES
    ('RUN-001', '컨테이너 셸 실행', '1.0.0', 'PROCESS_EXEC', 'PROCESS', 'EXEC',
     'DETECT', 'STABLE', '["FALCO"]', '["T1059"]', 60, 'Runtime Security'),
    ('RUN-002', '서비스 프로세스의 셸 실행', '1.0.0', 'PROCESS_EXEC', 'PROCESS', 'EXEC',
     'DETECT', 'STABLE', '["FALCO","TETRAGON"]', '["T1059","T1505.003"]', 20, 'Runtime Security'),
    ('RUN-003', 'ServiceAccount 토큰 접근', '1.0.0', 'FILE_ACCESS', 'FILE', 'OPEN',
     'DETECT', 'STABLE', '["FALCO"]', '["T1552.007"]', 30, 'Runtime Security'),
    ('RUN-004', '실행 중인 컨테이너의 패키지 관리자 실행', '1.0.0', 'PROCESS_EXEC', 'PROCESS', 'EXEC',
     'DETECT', 'STABLE', '["FALCO"]', '["T1105"]', 20, 'Runtime Security'),
    ('RUN-005', 'Pod의 IMDS 접근', '0.1.0', 'NETWORK_CONNECT', 'NETWORK', 'CONNECT',
     'DRAFT', 'EXPERIMENTAL', '["TETRAGON","FALCO"]', '["T1552.005"]', 30, 'Runtime Security'),
    ('RUN-006', '다른 프로세스의 메모리 접근', '0.2.0', 'PROCESS_ACCESS', 'PROCESS', 'ACCESS',
     'DETECT', 'STABLE', '["FALCO"]', '["T1055"]', 20, 'Runtime Security'),
    ('RUN-007', '컨테이너 중요 경로 변경', '1.0.0', 'FILE_WRITE', 'FILE', 'WRITE',
     'DETECT', 'STABLE', '["FALCO"]', '["T1562.001"]', 100, 'Runtime Security'),
    ('RUN-008', '예상하지 않은 외부 연결', '0.1.0', 'NETWORK_CONNECT', 'NETWORK', 'CONNECT',
     'DRAFT', 'EXPERIMENTAL', '["TETRAGON","FALCO"]', '["T1041"]', 300, 'Runtime Security'),
    ('RUN-009', 'Privileged 컨테이너 실행', '0.1.0', 'CONTAINER_START', 'CONTAINER', 'START',
     'DRAFT', 'EXPERIMENTAL', '["FALCO","K8S_AUDIT"]', '["T1610"]', 10, 'Runtime Security'),
    ('RUN-010', '위험 Linux Capability 보유', '0.1.0', 'CONTAINER_START', 'CONTAINER', 'START',
     'DRAFT', 'EXPERIMENTAL', '["FALCO","K8S_AUDIT"]', '["T1610"]', 10, 'Runtime Security'),
    ('RUN-011', 'Host Namespace 진입', '0.1.0', 'PROCESS_PRIVILEGE', 'PROCESS', 'NAMESPACE_ENTER',
     'DRAFT', 'EXPERIMENTAL', '["FALCO","TETRAGON"]', '["T1611"]', 10, 'Runtime Security'),
    ('RUN-012', '민감 Host Mount 또는 Device 접근', '0.1.0', 'FILE_ACCESS', 'FILE', 'OPEN',
     'DRAFT', 'EXPERIMENTAL', '["FALCO","K8S_AUDIT"]', '["T1611"]', 20, 'Runtime Security'),
    ('RUN-013', 'Container Escape 징후', '1.0.0', 'FILE_WRITE', 'FILE', 'WRITE',
     'DETECT', 'STABLE', '["FALCO"]', '["T1611"]', 10, 'Runtime Security'),
    ('RUN-014', '신규 Binary 생성 후 실행', '1.0.0', 'PROCESS_EXEC', 'PROCESS', 'EXEC',
     'DETECT', 'STABLE', '["FALCO"]', '["T1105","T1059"]', 30, 'Runtime Security'),
    ('RUN-015', '쓰기 가능한 임시 경로에서 실행', '0.5.0', 'PROCESS_EXEC', 'PROCESS', 'EXEC',
     'OBSERVE', 'INCUBATING', '["FALCO"]', '["T1059"]', 100, 'Runtime Security'),
    ('RUN-016', 'Reverse Shell 징후', '1.0.0', 'NETWORK_ACTIVITY', 'PROCESS', 'CONNECT',
     'DETECT', 'STABLE', '["FALCO"]', '["T1059","T1059.004"]', 20, 'Runtime Security'),
    ('RUN-017', '다운로드 도구 실행', '0.5.0', 'PROCESS_EXEC', 'PROCESS', 'EXEC',
     'OBSERVE', 'INCUBATING', '["FALCO"]', '["T1105"]', 100, 'Runtime Security'),
    ('RUN-018', '비표준 Port의 SSH 연결', '0.5.0', 'NETWORK_ACTIVITY', 'PROCESS', 'CONNECT',
     'OBSERVE', 'INCUBATING', '["FALCO"]', '["T1021.004"]', 30, 'Runtime Security'),
    ('RUN-019', 'Cloud Credential 탐색', '1.0.0', 'PROCESS_EXEC', 'PROCESS', 'DISCOVER',
     'DETECT', 'STABLE', '["FALCO"]', '["T1552.001"]', 20, 'Runtime Security'),
    ('RUN-020', '사용자·권한 파일 변경', '0.5.0', 'FILE_WRITE', 'FILE', 'WRITE',
     'OBSERVE', 'INCUBATING', '["FALCO"]', '["T1136","T1098"]', 30, 'Runtime Security'),
    ('RUN-021', 'Cron·서비스 지속성 등록', '0.5.0', 'FILE_WRITE', 'FILE', 'WRITE',
     'OBSERVE', 'INCUBATING', '["FALCO"]', '["T1053.003","T1543.002"]', 30, 'Runtime Security'),
    ('RUN-022', 'SSH authorized_keys 변경', '1.0.0', 'FILE_WRITE', 'FILE', 'WRITE',
     'DETECT', 'STABLE', '["FALCO"]', '["T1098.004"]', 10, 'Runtime Security'),
    ('RUN-023', '로그 삭제 또는 흔적 제거', '1.0.0', 'FILE_WRITE', 'FILE', 'DELETE',
     'DETECT', 'STABLE', '["FALCO"]', '["T1070.002"]', 30, 'Runtime Security'),
    ('RUN-024', 'setuid·Capability 변경', '0.5.0', 'PROCESS_PRIVILEGE', 'PROCESS', 'PRIVILEGE_CHANGE',
     'OBSERVE', 'INCUBATING', '["FALCO"]', '["T1548.001"]', 30, 'Runtime Security')
ON CONFLICT (rule_key) DO UPDATE SET
    title = EXCLUDED.title,
    version = EXCLUDED.version,
    event_type = EXCLUDED.event_type,
    target_type = EXCLUDED.target_type,
    operation = EXCLUDED.operation,
    mode = EXCLUDED.mode,
    maturity = EXCLUDED.maturity,
    sensors = EXCLUDED.sensors,
    mitre_techniques = EXCLUDED.mitre_techniques,
    noise_budget_per_minute = EXCLUDED.noise_budget_per_minute,
    owner = EXCLUDED.owner,
    updated_at = CURRENT_TIMESTAMP;

ALTER TABLE runtime_rules
    ALTER COLUMN operation SET NOT NULL;

INSERT INTO runtime_rule_sensor_mappings (sensor_type, source_rule, rule_key) VALUES
    ('FALCO', 'Logssey RUN-001 Container Shell', 'RUN-001'),
    ('FALCO', 'Terminal shell in container', 'RUN-001'),
    ('FALCO', 'Logssey RUN-002 Service Process Shell', 'RUN-002'),
    ('FALCO', 'Logssey RUN-003 ServiceAccount Token Access', 'RUN-003'),
    ('FALCO', 'Logssey RUN-004 Package Manager Execution', 'RUN-004'),
    ('FALCO', 'PTRACE attached to process', 'RUN-006'),
    ('FALCO', 'Logssey RUN-007 Sensitive Path Write', 'RUN-007'),
    ('FALCO', 'Detect release_agent File Container Escapes', 'RUN-013'),
    ('FALCO', 'Drop and execute new binary in container', 'RUN-014'),
    ('FALCO', 'Logssey RUN-015 Writable Path Execution', 'RUN-015'),
    ('FALCO', 'Netcat Remote Code Execution in Container', 'RUN-016'),
    ('FALCO', 'Redirect STDOUT/STDIN to Network Connection in Container', 'RUN-016'),
    ('FALCO', 'Logssey RUN-017 Downloader Execution', 'RUN-017'),
    ('FALCO', 'Disallowed SSH Connection Non Standard Port', 'RUN-018'),
    ('FALCO', 'Find AWS Credentials', 'RUN-019'),
    ('FALCO', 'Logssey RUN-020 Identity File Change', 'RUN-020'),
    ('FALCO', 'Logssey RUN-021 Persistence File Change', 'RUN-021'),
    ('FALCO', 'Logssey RUN-022 Authorized Keys Change', 'RUN-022'),
    ('FALCO', 'Clear Log Activities', 'RUN-023'),
    ('FALCO', 'Logssey RUN-024 Privilege Change', 'RUN-024')
ON CONFLICT (sensor_type, source_rule) DO UPDATE SET rule_key = EXCLUDED.rule_key;

ALTER TABLE runtime_events
    ADD COLUMN rule_mode VARCHAR(20) NOT NULL DEFAULT 'DETECT'
        CHECK (rule_mode IN ('DETECT', 'OBSERVE'));

ALTER TABLE runtime_events
    DROP CONSTRAINT ck_runtime_event_suppression;
ALTER TABLE runtime_events
    DROP CONSTRAINT runtime_events_handling_status_check;
ALTER TABLE runtime_events
    ADD CONSTRAINT runtime_events_handling_status_check
        CHECK (handling_status IN ('GROUPED', 'SUPPRESSED', 'OBSERVED')),
    ADD CONSTRAINT ck_runtime_event_suppression CHECK (
        (handling_status IN ('GROUPED', 'OBSERVED') AND suppression_id IS NULL)
        OR (handling_status = 'SUPPRESSED' AND suppression_id IS NOT NULL)
    );

ALTER TABLE runtime_raw_events
    DROP CONSTRAINT runtime_raw_events_processing_status_check;
ALTER TABLE runtime_raw_events
    ADD CONSTRAINT runtime_raw_events_processing_status_check CHECK (processing_status IN (
        'RECEIVED', 'IGNORED', 'NORMALIZED', 'ASSET_RESOLVED', 'ASSET_UNRESOLVED',
        'GROUPED', 'SUPPRESSED', 'OBSERVED', 'RATE_LIMITED', 'FAILED'
    ));

CREATE INDEX idx_runtime_events_observed
    ON runtime_events (rule_key, occurred_at DESC)
    WHERE handling_status = 'OBSERVED';
