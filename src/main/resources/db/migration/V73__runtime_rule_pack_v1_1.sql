UPDATE runtime_rules
SET pack_version = '1.1.0',
    updated_at = CURRENT_TIMESTAMP;

UPDATE runtime_rules
SET title = '대화형 컨테이너 셸 실행',
    version = '1.1.0',
    updated_at = CURRENT_TIMESTAMP
WHERE rule_key = 'RUN-001';

UPDATE runtime_rules
SET version = '1.1.0',
    updated_at = CURRENT_TIMESTAMP
WHERE rule_key IN ('RUN-003', 'RUN-007');

UPDATE runtime_rules
SET version = '0.6.0',
    noise_budget_per_minute = 20,
    updated_at = CURRENT_TIMESTAMP
WHERE rule_key = 'RUN-017';

UPDATE runtime_rules
SET title = 'root UID·GID 또는 위험 Capability 획득',
    version = '0.6.0',
    noise_budget_per_minute = 10,
    updated_at = CURRENT_TIMESTAMP
WHERE rule_key = 'RUN-024';

DELETE FROM runtime_rule_sensor_mappings
WHERE sensor_type = 'FALCO'
  AND source_rule = 'Terminal shell in container'
  AND rule_key = 'RUN-001';
