-- IaC 보안 ③ 드리프트 규칙 (rule-spec.md "③ State·드리프트"). V11 시드에서 빠진 것.
INSERT INTO iac_rules (rule_id, engine, default_enforcement, default_severity, template_key, version) VALUES
    ('drift.high',   'DRIFT', 'WARN', 'HIGH',   'drift.high',   '1'),
    ('drift.medium', 'DRIFT', 'INFO', 'MEDIUM', 'drift.medium', '1'),
    ('drift.low',    'DRIFT', 'INFO', 'LOW',    'drift.low',    '1');
