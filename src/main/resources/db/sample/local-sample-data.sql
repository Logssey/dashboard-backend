-- 로컬(local 프로필) 전용 샘플 데이터. 운영 환경에서는 실행되지 않는다.
-- LocalSampleDataLoader가 서버를 켤 때마다 이 파일을 실행한다.
-- 매번 샘플 행만 지우고, 발생 시각을 "켠 시점 기준 최근 7일"로 다시 계산해 넣는다.
-- 샘플이 아닌 행(스캔으로 발견한 키 등)은 지우지 않는다 (Secret 데이터베이스 스키마 문서 6장).

-- 샘플 탐지 이벤트 8건 + 예전 버전이 키 위험 판단으로 만들었던 이벤트(credential_id 연결)
-- 예전 이벤트 정리는 Secret을 detection_events에 넣지 않기로 하면서 남은 로컬 데이터를 치우는 용도다
DELETE FROM detection_events
WHERE display_id IN ('CFG-001', 'SEC-001', 'IAM-001', 'RUN-001', 'CFG-002', 'IAM-002', 'RUN-002', 'VUL-001')
   OR credential_id IS NOT NULL;

-- 샘플 키 5개 (Notion Admin API 형식을 본뜬 가상 목록)
DELETE FROM credentials
WHERE source = 'API' AND external_id LIKE 'sample-pat-%';

-- 샘플 자산 8개. 다른 이벤트가 아직 참조하면 지우지 않고 그대로 쓴다
DELETE FROM assets a
WHERE (a.provider, a.name, a.environment) IN (
        ('AWS',        'logssey-prod-sg-rds',                    'PROD'),
        ('GITHUB',     'service-backend/application.properties', 'PROD'),
        ('KUBERNETES', 'api-service-account',                    'PROD'),
        ('KUBERNETES', 'reused-api-7c4b',                        'PROD'),
        ('AWS',        'reused-assets',                          'PROD'),
        ('AWS',        'ci-legacy-user',                         'DEV'),
        ('KUBERNETES', 'reused-chat',                            'DEV'),
        ('AWS',        'logssey/reused-api:demo',                'PROD'))
  AND NOT EXISTS (SELECT 1 FROM detection_events e WHERE e.asset_id = a.asset_id);

-- 자산 (확인된 실제 Re:Used 리소스 이름으로 맞춤. 확인 안 된 것은 템플릿 이름 유지)
INSERT INTO assets (name, provider, asset_type, environment) VALUES
    ('logssey-prod-sg-rds',                    'AWS',        'Security Group',  'PROD'),
    ('service-backend/application.properties', 'GITHUB',     'Config File',     'PROD'),
    ('api-service-account',                    'KUBERNETES', 'ServiceAccount',  'PROD'),
    ('reused-api-7c4b',                        'KUBERNETES', 'Pod',             'PROD'),
    ('reused-assets',                          'AWS',        'S3 Bucket',       'PROD'),
    ('ci-legacy-user',                         'AWS',        'IAM User',        'DEV'),
    ('reused-chat',                            'KUBERNETES', 'Deployment',      'DEV'),
    ('logssey/reused-api:demo',                'AWS',        'Container Image', 'PROD')
ON CONFLICT (provider, name, environment) DO NOTHING;

-- 탐지 이벤트 8건 (진호 님 UI 템플릿 예시. 실제 탐지 결과가 아님)
INSERT INTO detection_events
    (asset_id, display_id, severity, title, environment, owner_team, detected_at, domain, evidence, recommendation)
VALUES
    ((SELECT asset_id FROM assets WHERE name = 'logssey-prod-sg-rds'),
     'CFG-001', 'CRITICAL', '데이터베이스 접근 범위 확인 필요', 'PROD', 'Cloud Ops', now() - interval '6 days',
     'CONFIGURATION',
     E'설정 기준: 데이터베이스 접근 범위 제한\n현재 상태: 허용 범위 검토 필요\n수집 소스: 가상 설정 스냅샷',
     '서비스에 필요한 접근 범위를 확인하고 보안 그룹의 허용 대상을 검토합니다.'),

    ((SELECT asset_id FROM assets WHERE name = 'service-backend/application.properties'),
     'SEC-001', 'CRITICAL', '설정 파일에서 인증정보 참조 발견', 'PROD', 'Backend', now() - interval '5 days',
     'SECRETS',
     E'값: [REDACTED — DEMO]\n유효성: 확인하지 않음\n수집 소스: 가상 코드 점검',
     '사용처와 소유자를 확인한 뒤 비밀 저장소 이전 및 교체 계획을 검토합니다.'),

    ((SELECT asset_id FROM assets WHERE name = 'api-service-account'),
     'IAM-001', 'HIGH', '서비스 계정의 관리자 권한 검토 필요', 'PROD', 'Platform', now() - interval '4 days',
     'IDENTITIES',
     E'연결 역할: cluster-admin\n관찰 기간: 최근 7일 예시\n유효 권한 계산: 미구현',
     '워크로드에 필요한 작업을 확인하고 역할의 권한 범위를 검토합니다.'),

    ((SELECT asset_id FROM assets WHERE name = 'reused-api-7c4b'),
     'RUN-001', 'HIGH', '컨테이너에서 예상하지 않은 셸 실행', 'PROD', 'AppSec', now() - interval '3 days',
     'RUNTIME',
     E'이벤트: process execution\n프로세스: /bin/sh\n출처: 합성 런타임 이벤트\n공격 여부: 미확정',
     '배포 및 운영 작업 이력과 대조하고 해당 이벤트가 승인된 작업인지 확인합니다.'),

    ((SELECT asset_id FROM assets WHERE name = 'reused-assets'),
     'CFG-002', 'MEDIUM', '스토리지 접근 기록 수집 비활성화', 'PROD', 'Cloud Ops', now() - interval '2 days',
     'CONFIGURATION',
     E'점검 항목: 접근 기록 수집\n현재 값: 비활성화\n권장 값: 활성화',
     '로그 저장 위치와 보존 기간을 정한 뒤 접근 기록 수집을 설정합니다.'),

    ((SELECT asset_id FROM assets WHERE name = 'ci-legacy-user'),
     'IAM-002', 'MEDIUM', '최근 사용 기록이 없는 계정 검토 필요', 'DEV', 'Platform', now() - interval '1 day',
     'IDENTITIES',
     E'관찰 기간: 최근 30일 예시\n관찰된 사용: 없음\n미사용 확정: 아님',
     '배치 주기와 서비스 의존성을 확인한 뒤 계정 정리 여부를 결정합니다.'),

    ((SELECT asset_id FROM assets WHERE name = 'reused-chat'),
     'RUN-002', 'MEDIUM', '워크로드의 새로운 외부 연결 관찰', 'DEV', 'Backend', now() - interval '1 day',
     'RUNTIME',
     E'이벤트: outbound connection\n대상: api.example.test\n최초 관찰: 데모 시점',
     '예정된 외부 서비스 연동인지 확인하고 연결 이력을 검토합니다.'),

    ((SELECT asset_id FROM assets WHERE name = 'logssey/reused-api:demo'),
     'VUL-001', 'HIGH', '베이스 이미지 보안 업데이트 확인', 'PROD', 'AppSec', now(),
     'VULNERABILITIES',
     E'이미지: logssey/reused-api:demo\n패키지: 가상 예시\n업데이트: 검토 필요',
     '수정 버전의 호환성을 검증한 뒤 새 이미지를 빌드하고 배포합니다.');

-- 런타임 보안 샘플. Falco RUN-001 한 건을 수집·정규화·Finding으로 묶은 상태를 재현한다.
DELETE FROM runtime_finding_events
WHERE runtime_event_id IN (
    SELECT runtime_event_id FROM runtime_events WHERE source_event_id = 'sample-falco-run-001');
DELETE FROM runtime_findings WHERE fingerprint = repeat('a', 64);
DELETE FROM runtime_events WHERE source_event_id = 'sample-falco-run-001';
DELETE FROM runtime_raw_events WHERE source_event_id = 'sample-falco-run-001';
DELETE FROM runtime_assets
WHERE cluster_id = 'logssey-prod' AND container_id = 'sample-container-reused-api';
DELETE FROM runtime_sensors
WHERE cluster_id = 'logssey-prod' AND node_name IN ('worker-a', 'worker-c', 'worker-d') AND sensor_type = 'FALCO';

INSERT INTO assets (name, provider, asset_type, environment)
VALUES ('reused-api', 'KUBERNETES', 'Deployment', 'PROD')
ON CONFLICT (provider, name, environment) DO NOTHING;

INSERT INTO runtime_sensors
    (cluster_id, node_name, sensor_type, version, driver, rule_set_version, status,
     last_heartbeat_at, last_event_at, queue_depth)
VALUES
    ('logssey-prod', 'worker-a', 'FALCO', '0.45.0', 'modern_ebpf', 'logssey-0.1.0', 'HEALTHY', now(), now() - interval '8 minutes', 0),
    ('logssey-prod', 'worker-c', 'FALCO', '0.45.0', 'modern_ebpf', 'logssey-0.1.0', 'HEALTHY', now(), now() - interval '21 minutes', 0),
    ('logssey-prod', 'worker-d', 'FALCO', '0.45.0', 'modern_ebpf', 'logssey-0.1.0', 'HEALTHY', now(), NULL, 0);

INSERT INTO runtime_assets
    (asset_id, cluster_id, namespace, workload_kind, workload_name, pod_uid, pod_name,
     container_id, container_name, image, image_digest, node_name, service_account_name,
     valid_from, snapshot_at)
VALUES
    ((SELECT asset_id FROM assets
      WHERE provider = 'KUBERNETES' AND name = 'reused-api' AND environment = 'PROD'),
     'logssey-prod', 'reused', 'Deployment', 'reused-api', 'sample-pod-uid-reused-api',
     'reused-api-7d9df64b9f-k2j9p', 'sample-container-reused-api', 'api',
     'logssey/reused-api:demo', 'sha256:sample', 'worker-a', 'reused-api',
     now() - interval '38 minutes', now() - interval '8 minutes');

INSERT INTO runtime_raw_events
    (cluster_id, sensor_type, sensor_id, source_event_id, idempotency_key, schema_version,
     payload, masked_fields, processing_status, received_at)
VALUES
    ('logssey-prod', 'FALCO',
     (SELECT sensor_id FROM runtime_sensors
      WHERE cluster_id = 'logssey-prod' AND node_name = 'worker-a' AND sensor_type = 'FALCO'),
     'sample-falco-run-001', 'sample-falco-run-001', 'falco-json-0.1',
     '{"uuid":"sample-falco-run-001","priority":"Warning","output_fields":{"proc.name":"bash","proc.exepath":"/usr/bin/bash","proc.cmdline":"bash -c whoami","proc.pexepath":"/usr/bin/containerd-shim-runc-v2","user.uid":"1000","container.id":"sample-container-reused-api","k8s.ns.name":"reused","k8s.pod.name":"reused-api-7d9df64b9f-k2j9p"}}'::jsonb,
     '[]'::jsonb, 'GROUPED', now() - interval '8 minutes');

INSERT INTO runtime_events
    (raw_event_id, runtime_asset_id, source, source_event_id, event_type, rule_key, rule_version,
     source_priority, occurred_at, received_at, process_id, parent_process_id, process_executable,
     process_arguments, parent_executable, user_id, normalization_status, missing_fields,
     asset_resolution_status, target_type, target_name, operation)
VALUES
    ((SELECT raw_event_id FROM runtime_raw_events WHERE source_event_id = 'sample-falco-run-001'),
     (SELECT runtime_asset_id FROM runtime_assets
      WHERE cluster_id = 'logssey-prod' AND container_id = 'sample-container-reused-api'),
     'FALCO', 'sample-falco-run-001', 'PROCESS_EXEC', 'RUN-001', '0.1.0', 'WARNING',
     now() - interval '8 minutes', now() - interval '8 minutes', 121, 87, '/usr/bin/bash',
     '["bash", "-c", "whoami"]'::jsonb, '/usr/bin/containerd-shim-runc-v2', '1000',
     'COMPLETE', '[]'::jsonb, 'RESOLVED', 'PROCESS', '/usr/bin/bash', 'EXEC');

INSERT INTO runtime_findings
    (fingerprint, rule_key, rule_title, rule_version, runtime_asset_id, asset_id, source_priority,
     evaluation_status, first_seen_at, last_seen_at, occurrence_count, process_executable,
     parent_executable, user_id, target_type, target_name, operation)
VALUES
    (repeat('a', 64), 'RUN-001', '컨테이너 셸 실행', '0.1.0',
     (SELECT runtime_asset_id FROM runtime_assets
      WHERE cluster_id = 'logssey-prod' AND container_id = 'sample-container-reused-api'),
     (SELECT asset_id FROM assets
      WHERE provider = 'KUBERNETES' AND name = 'reused-api' AND environment = 'PROD'),
     'WARNING', 'PENDING_CONTEXT', now() - interval '38 minutes', now() - interval '8 minutes', 3,
     '/usr/bin/bash', '/usr/bin/containerd-shim-runc-v2', '1000', 'PROCESS', '/usr/bin/bash', 'EXEC');

INSERT INTO runtime_finding_events (finding_id, runtime_event_id)
VALUES
    ((SELECT finding_id FROM runtime_findings WHERE fingerprint = repeat('a', 64)),
     (SELECT runtime_event_id FROM runtime_events WHERE source_event_id = 'sample-falco-run-001'));


-- 키 샘플 5개 (Notion PAT. Notion Admin API 응답 형식을 본뜬 가상 데이터)
-- 발급처 목록 정보일 뿐이라 위험 등급을 매기지 않는다. 만료·미사용은 목록에 보여주는 정보다.
-- 키 원문은 넣지 않는다 (Secret ADR-S005). Notion은 assets에 넣지 않으므로 asset_id는 비운다.
INSERT INTO credentials
    (issuer, credential_type, classification, display_name, external_id, owner, owner_team, purpose,
     status, source, issued_at, expiry_policy, expires_at, last_used_at, last_collected_at)
VALUES
    -- 평범한 활성 키
    ('NOTION', 'NOTION_PAT', 'SECRET', 'deploy-bot',    'sample-pat-0001', 'Team Member A', 'Platform', '배포 결과 기록',
     'ACTIVE',  'API', now() - interval '120 days', 'FIXED', now() + interval '90 days', now() - interval '1 day',   now()),
    -- 5일 뒤 만료
    ('NOTION', 'NOTION_PAT', 'SECRET', 'notion-sync',   'sample-pat-0002', 'Team Member B', 'Backend',  '회의록 동기화',
     'ACTIVE',  'API', now() - interval '360 days', 'FIXED', now() + interval '5 days',  now() - interval '1 day',   now()),
    -- 60일 전 마지막 사용
    ('NOTION', 'NOTION_PAT', 'SECRET', 'old-script',    'sample-pat-0003', 'Team Member A', 'Platform', '일회성 데이터 이전',
     'ACTIVE',  'API', now() - interval '200 days', 'FIXED', now() + interval '90 days', now() - interval '60 days', now()),
    -- 만료일 없음
    ('NOTION', 'NOTION_PAT', 'SECRET', 'legacy-export', 'sample-pat-0004', 'Team Member C', 'AppSec',   '문서 내보내기',
     'ACTIVE',  'API', now() - interval '30 days',  'NEVER', NULL,                       now() - interval '1 day',   now()),
    -- 폐기됨
    ('NOTION', 'NOTION_PAT', 'SECRET', 'revoked-tool',  'sample-pat-0005', 'Team Member B', 'Backend',  '테스트 연동',
     'REVOKED', 'API', now() - interval '150 days', 'FIXED', now() + interval '30 days', now() - interval '40 days', now());

-- Reach 샘플: PoC api 이미지 1개, 스캔 1개, Finding 23개 (프론트 src/api/reachSample.ts와 같은 값)
-- 샘플 대상(digest sha256:sample-reach-api)에 딸린 행만 지운다. 실제 스캔 결과는 남는다
-- 실제 결과가 샘플을 가리키면(샘플 검토를 이어받음, 샘플 스캔을 재대조·기준 스캔으로 씀) 그 연결을 먼저 끊는다. 안 끊으면 아래 삭제가 FK에 막힌다
UPDATE reach_reviews SET carried_from_finding_id = NULL, carried_from_scan_id = NULL
WHERE carried_from_scan_id IN (SELECT s.scan_id FROM reach_scans s
                               JOIN reach_targets t ON t.target_id = s.target_id
                               WHERE t.image_digest = 'sha256:sample-reach-api');
UPDATE reach_scans SET rescan_of_scan_id = NULL
WHERE rescan_of_scan_id IN (SELECT s.scan_id FROM reach_scans s
                            JOIN reach_targets t ON t.target_id = s.target_id
                            WHERE t.image_digest = 'sha256:sample-reach-api');
UPDATE reach_ci_checks SET baseline_scan_id = NULL
WHERE baseline_scan_id IN (SELECT s.scan_id FROM reach_scans s
                           JOIN reach_targets t ON t.target_id = s.target_id
                           WHERE t.image_digest = 'sha256:sample-reach-api');
-- 샘플 스캔을 재대조한 검사(API-01 rescanOf)는 샘플 대상의 스캔을 가리키니 같이 지운다
DELETE FROM reach_ci_checks
WHERE scan_id IN (SELECT s.scan_id FROM reach_scans s
                  JOIN reach_targets t ON t.target_id = s.target_id
                  WHERE t.image_digest = 'sha256:sample-reach-api');
DELETE FROM reach_review_history
WHERE finding_id IN (SELECT f.finding_id FROM reach_findings f
                     JOIN reach_targets t ON t.target_id = f.target_id
                     WHERE t.image_digest = 'sha256:sample-reach-api');
DELETE FROM reach_reviews
WHERE finding_id IN (SELECT f.finding_id FROM reach_findings f
                     JOIN reach_targets t ON t.target_id = f.target_id
                     WHERE t.image_digest = 'sha256:sample-reach-api');
DELETE FROM reach_evidence
WHERE verdict_id IN (SELECT v.verdict_id FROM reach_verdicts v
                     JOIN reach_findings f ON f.finding_id = v.finding_id
                     JOIN reach_targets t ON t.target_id = f.target_id
                     WHERE t.image_digest = 'sha256:sample-reach-api');
DELETE FROM reach_verdicts
WHERE finding_id IN (SELECT f.finding_id FROM reach_findings f
                     JOIN reach_targets t ON t.target_id = f.target_id
                     WHERE t.image_digest = 'sha256:sample-reach-api');
DELETE FROM reach_findings
WHERE target_id IN (SELECT target_id FROM reach_targets WHERE image_digest = 'sha256:sample-reach-api');
DELETE FROM reach_scans
WHERE target_id IN (SELECT target_id FROM reach_targets WHERE image_digest = 'sha256:sample-reach-api');
DELETE FROM reach_targets
WHERE image_repository = 'logssey/reused-api' AND image_digest = 'sha256:sample-reach-api';

INSERT INTO reach_targets (target_type, app, image_repository, image_digest, display_name)
VALUES ('IMAGE', 'API', 'logssey/reused-api', 'sha256:sample-reach-api', 'reused-api');

INSERT INTO reach_scans
    (target_id, scan_status, trigger_type, requested_by_kind, tools, created_at, started_at, finished_at)
SELECT target_id, 'SUCCEEDED', 'MANUAL', 'SYSTEM', '{"reach": "v0", "scanner": "trivy"}',
       now() - interval '1 hour', now() - interval '1 hour', now() - interval '55 minutes'
FROM reach_targets WHERE image_digest = 'sha256:sample-reach-api';

-- 아래 INSERT들이 같이 쓰는 샘플 스캔과 Finding 원본. 행을 늘릴 때는 reach_sample_rows의 VALUES만 늘린다
DROP TABLE IF EXISTS reach_sample_scan;
CREATE TEMP TABLE reach_sample_scan AS
SELECT s.scan_id, s.target_id, s.finished_at
FROM reach_scans s JOIN reach_targets t ON t.target_id = s.target_id
WHERE t.image_digest = 'sha256:sample-reach-api';

DROP TABLE IF EXISTS reach_sample_rows;
CREATE TEMP TABLE reach_sample_rows (
    seq       INTEGER,
    severity  VARCHAR(10),
    cve       VARCHAR(40),
    name      VARCHAR(200),
    grp       VARCHAR(200),
    version   VARCHAR(100),
    fixed     TEXT[],
    status    VARCHAR(15),
    method    VARCHAR(10),
    reason    VARCHAR(30),
    review    VARCHAR(15),
    summary   VARCHAR(500),
    proposal  VARCHAR(500)
);
-- seq는 화면 기본 정렬 순서이고 Finding ID도 이 순서로 매긴다 (reachSample.ts의 rows 순서와 같음)
INSERT INTO reach_sample_rows VALUES
    -- Java 라이브러리 14개: 도달 불가 판정
    (1, 'CRITICAL', 'CVE-2025-14813', 'bcprov-jdk18on', 'org.bouncycastle', '1.81', ARRAY['1.80.2', '1.81.1', '1.84'],
     'UNREACHABLE', 'CALLGRAPH', NULL, 'CONFIRMED', '취약 메서드 G3413CTRBlockCipher.generateCRT에 닿는 경로 없음', NULL),
    (2, 'CRITICAL', 'CVE-2026-8763', 'bcprov-jdk18on', 'org.bouncycastle', '1.81', ARRAY['1.85'],
     'UNREACHABLE', 'CALLGRAPH', NULL, 'CONFIRMED', 'Name Constraints 검증 메서드에 닿지 않는다. BC provider·CertPathValidator 참조 없음', NULL),
    (3, 'CRITICAL', 'CVE-2026-65182', 'tomcat-embed-core', 'org.apache.tomcat.embed', '11.0.24', ARRAY['11.0.25'],
     'UNREACHABLE', 'RULE', NULL, 'CONFIRMED', '컨테이너 보안 제약(security-constraint, @ServletSecurity) 없음', NULL),
    (4, 'CRITICAL', 'CVE-2026-65905', 'tomcat-embed-core', 'org.apache.tomcat.embed', '11.0.24', ARRAY['11.0.25'],
     'UNREACHABLE', 'RULE', NULL, 'CONFIRMED', 'DIGEST 인증기 설정 없음', NULL),
    (5, 'CRITICAL', 'CVE-2026-68525', 'tomcat-embed-core', 'org.apache.tomcat.embed', '11.0.24', ARRAY['11.0.25', '10.1.58', '9.0.121'],
     'UNREACHABLE', 'RULE', NULL, 'CONFIRMED', 'FORM 인증(LoginConfig) 설정 없음', NULL),
    (6, 'HIGH', 'CVE-2026-13506', 'bcprov-jdk18on', 'org.bouncycastle', '1.81', ARRAY['1.85'],
     'UNREACHABLE', 'CALLGRAPH', NULL, 'PROVISIONAL', 'ASN.1 지연 파싱 메서드에 닿지 않는다. 패키지는 Argon2 경로로 닿는다', NULL),
    (7, 'HIGH', 'CVE-2026-68497', 'jackson-databind', 'tools.jackson.core', '3.1.5', ARRAY['3.1.6'],
     'UNREACHABLE', 'RULE', NULL, 'CONFIRMED', 'javax.xml.datatype(Duration, XMLGregorianCalendar) 사용 없음', NULL),
    (8, 'HIGH', 'CVE-2026-89407', 'jackson-core', 'tools.jackson.core', '3.1.5', ARRAY['3.1.7', '3.2.2'],
     'UNREACHABLE', 'RULE', NULL, 'CONFIRMED', 'Jackson에 타입을 알려줄 수 있는 자리(tokens 97개)의 타입에 실수형 필드 없음', NULL),
    (9, 'HIGH', 'CVE-2026-89425', 'jackson-core', 'tools.jackson.core', '3.1.5', ARRAY['3.1.7'],
     'UNREACHABLE', 'CALLGRAPH', NULL, 'CONFIRMED', 'DataInput 파서 메서드에 닿지 않는다. DataInput 사용 없음', NULL),
    (10, 'HIGH', 'CVE-2026-91776', 'jackson-databind', 'tools.jackson.core', '3.1.5', ARRAY['3.1.7'],
     'UNREACHABLE', 'RULE', NULL, 'CONFIRMED', '@JsonTypeInfo, default typing, 문제 처리기 사용 없음', NULL),
    (11, 'HIGH', 'CVE-2026-91777', 'jackson-databind', 'tools.jackson.core', '3.1.5', ARRAY['3.1.7'],
     'UNREACHABLE', 'RULE', NULL, 'CONFIRMED', '@JsonIdentityInfo 사용 없음', NULL),
    (12, 'MEDIUM', 'CVE-2026-0636', 'bcprov-jdk18on', 'org.bouncycastle', '1.81', ARRAY['1.84'],
     'UNREACHABLE', 'CALLGRAPH', NULL, 'CONFIRMED', 'LDAP 저장소 메서드(parseDN, search)에 닿지 않는다', NULL),
    (13, 'MEDIUM', 'CVE-2026-19032', 'jackson-databind', 'tools.jackson.core', '3.1.5', ARRAY['3.1.6'],
     'UNREACHABLE', 'RULE', NULL, 'CONFIRMED', '역직렬화 타입에 Path 필드 없음', NULL),
    (14, 'MEDIUM', 'CVE-2026-83557', 'jackson-databind', 'tools.jackson.core', '3.1.5', ARRAY['3.1.6'],
     'UNREACHABLE', 'RULE', NULL, 'CONFIRMED', '@JsonTypeInfo 사용 없음', NULL),
    -- Jackson 2 사본 7개: 판정하지 않음, 제안(확정 대기)만 있음
    (15, 'HIGH', 'CVE-2026-68497', 'jackson-databind', 'com.fasterxml.jackson.core', '2.21.5', ARRAY['2.21.6'],
     'NOT_ANALYZED', NULL, 'UNANALYZED_COPY', 'UNREVIEWED', '판정하지 않은 패키지 사본', '도달 불가(발동 조건 없음)'),
    (16, 'HIGH', 'CVE-2026-89407', 'jackson-core', 'com.fasterxml.jackson.core', '2.21.5', ARRAY['2.18.11', '2.21.7', '2.22.3'],
     'NOT_ANALYZED', NULL, 'UNANALYZED_COPY', 'UNREVIEWED', '판정하지 않은 패키지 사본',
     '도달 불가. 운영 기본에서 외부 입력을 Jackson 2로 읽는 경로가 없다. anthropic을 켜도 SDK 매퍼가 문자열→숫자 변환을 막는다'),
    (17, 'HIGH', 'CVE-2026-89425', 'jackson-core', 'com.fasterxml.jackson.core', '2.21.5', ARRAY['2.21.7'],
     'NOT_ANALYZED', NULL, 'UNANALYZED_COPY', 'UNREVIEWED', '판정하지 않은 패키지 사본', '도달 불가'),
    (18, 'HIGH', 'CVE-2026-91776', 'jackson-databind', 'com.fasterxml.jackson.core', '2.21.5', ARRAY['2.21.7'],
     'NOT_ANALYZED', NULL, 'UNANALYZED_COPY', 'UNREVIEWED', '판정하지 않은 패키지 사본', '도달 불가(발동 조건 없음)'),
    (19, 'HIGH', 'CVE-2026-91777', 'jackson-databind', 'com.fasterxml.jackson.core', '2.21.5', ARRAY['2.21.7'],
     'NOT_ANALYZED', NULL, 'UNANALYZED_COPY', 'UNREVIEWED', '판정하지 않은 패키지 사본', '도달 불가(발동 조건 없음)'),
    (20, 'MEDIUM', 'CVE-2026-19032', 'jackson-databind', 'com.fasterxml.jackson.core', '2.21.5', ARRAY['2.21.6'],
     'NOT_ANALYZED', NULL, 'UNANALYZED_COPY', 'UNREVIEWED', '판정하지 않은 패키지 사본', '도달 불가(발동 조건 없음)'),
    -- OS 패키지 2개는 Jackson 2 사본 사이에 있다 (CVE 번호 순서)
    (21, 'MEDIUM', 'CVE-2026-46675', 'libpng', 'alpine', '1.6.58-r1', ARRAY['1.6.59-r0'],
     'NOT_ANALYZED', NULL, 'OS_PACKAGE', 'UNREVIEWED', 'OS 패키지. Java 호출 그래프로 판정하지 않는다', NULL),
    (22, 'MEDIUM', 'CVE-2026-83557', 'jackson-databind', 'com.fasterxml.jackson.core', '2.21.5', ARRAY['2.21.6'],
     'NOT_ANALYZED', NULL, 'UNANALYZED_COPY', 'UNREVIEWED', '판정하지 않은 패키지 사본', '도달 불가(발동 조건 없음)'),
    (23, 'MEDIUM', 'CVE-2026-85091', 'zlib', 'alpine', '1.3.2-r0', ARRAY['1.3.2-r1'],
     'NOT_ANALYZED', NULL, 'OS_PACKAGE', 'UNREVIEWED', 'OS 패키지. Java 호출 그래프로 판정하지 않는다', NULL);

INSERT INTO reach_findings
    (target_id, purl, component_name, component_version, ecosystem, vulnerability_id, severity,
     fixed_versions, sources, deployment, last_scan_id, first_seen_at, last_seen_at)
SELECT s.target_id,
       CASE WHEN r.grp = 'alpine' THEN 'pkg:apk/alpine/' || r.name || '@' || r.version
            ELSE 'pkg:maven/' || r.grp || '/' || r.name || '@' || r.version END,
       r.name, r.version, CASE WHEN r.grp = 'alpine' THEN 'apk' ELSE 'maven' END,
       r.cve, r.severity, r.fixed, ARRAY['TRIVY'], 'RUNNING', s.scan_id, s.finished_at, s.finished_at
FROM reach_sample_rows r CROSS JOIN reach_sample_scan s
ORDER BY r.seq;

-- 도구 판정이라 engine과 evidence_hash가 필요하다. 샘플은 자리만 채운다
INSERT INTO reach_verdicts
    (finding_id, scan_id, status, method, not_analyzed_reason, summary, rule_id,
     engine, evidence_hash, is_current, analyzed_at)
SELECT f.finding_id, s.scan_id, r.status, r.method, r.reason, r.summary,
       CASE WHEN r.method = 'RULE' THEN 'RULE-' || r.cve END,
       '{"reach": "v0"}', repeat('0', 64), TRUE, s.finished_at
FROM reach_sample_rows r
CROSS JOIN reach_sample_scan s
JOIN reach_findings f ON f.last_scan_id = s.scan_id AND f.component_name = r.name
                     AND f.component_version = r.version AND f.vulnerability_id = r.cve;

-- 기본 근거 한 줄: 규칙 판정은 RULE, 나머지는 판정 요약을 NOTE로
INSERT INTO reach_evidence (verdict_id, ord, kind, summary, rule_id, detail)
SELECT v.verdict_id, 1, CASE WHEN v.method = 'RULE' THEN 'RULE' ELSE 'NOTE' END, v.summary, v.rule_id,
       CASE WHEN v.method = 'RULE' THEN '{"matchedCondition": "UNREACHABLE"}'::JSONB ELSE '{}'::JSONB END
FROM reach_verdicts v JOIN reach_sample_scan s ON s.scan_id = v.scan_id;

-- 검토자는 ADMIN 계정이다. 빈 DB로 처음 켜면 계정이 샘플보다 늦게 만들어질 수 있어 그때는 UNREVIEWED로 넣는다
INSERT INTO reach_reviews
    (finding_id, review_state, status, note, proposal, reviewer_user_id, reviewed_at, version, base_verdict_id)
SELECT f.finding_id,
       CASE WHEN r.review <> 'UNREVIEWED' AND u.user_id IS NOT NULL THEN r.review ELSE 'UNREVIEWED' END,
       CASE WHEN r.review <> 'UNREVIEWED' AND u.user_id IS NOT NULL THEN v.status END,
       CASE WHEN r.review = 'CONFIRMED' AND u.user_id IS NOT NULL THEN 'PoC 정답지(answer-key.md)와 같은 판정'
            WHEN r.review = 'PROVISIONAL' AND u.user_id IS NOT NULL THEN 'PoC 조사 결과. 확정 전에 한 번 더 확인한다' END,
       CASE WHEN r.proposal IS NOT NULL THEN jsonb_build_object(
            'status', 'UNREACHABLE', 'summary', r.proposal, 'reference', '규칙명세서 9-1, PoC 작업 기록 15-7절') END,
       CASE WHEN r.review <> 'UNREVIEWED' THEN u.user_id END,
       CASE WHEN r.review <> 'UNREVIEWED' AND u.user_id IS NOT NULL THEN s.finished_at + interval '10 minutes' END,
       CASE WHEN r.review <> 'UNREVIEWED' AND u.user_id IS NOT NULL THEN 2 ELSE 1 END,
       v.verdict_id
FROM reach_sample_rows r
CROSS JOIN reach_sample_scan s
JOIN reach_findings f ON f.last_scan_id = s.scan_id AND f.component_name = r.name
                     AND f.component_version = r.version AND f.vulnerability_id = r.cve
JOIN reach_verdicts v ON v.finding_id = f.finding_id AND v.is_current
LEFT JOIN LATERAL (SELECT user_id FROM dashboard_users WHERE role = 'ADMIN' ORDER BY user_id LIMIT 1) u ON TRUE;

DROP TABLE reach_sample_rows;
DROP TABLE reach_sample_scan;
