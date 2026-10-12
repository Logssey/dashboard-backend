-- 로컬(local 프로필) 전용 샘플 데이터. 운영 환경에서는 실행되지 않는다.
-- LocalSampleDataLoader가 서버를 켤 때마다 이 파일을 실행한다.
-- 매번 기존 샘플을 지우고, 발생 시각을 "켠 시점 기준 최근 7일"로 다시 계산해 넣는다.
-- 주의: 로컬 DB의 탐지 이벤트, 키, 자산을 전부 지운 뒤 다시 넣는다.

DELETE FROM detection_events;
DELETE FROM credentials;
DELETE FROM assets;

-- 자산 (확인된 실제 Re:Used 리소스 이름으로 맞춤. 확인 안 된 것은 템플릿 이름 유지)
INSERT INTO assets (name, provider, asset_type, environment) VALUES
    ('logssey-prod-sg-rds',                    'AWS',        'Security Group',  'PROD'),
    ('service-backend/application.properties', 'GITHUB',     'Config File',     'PROD'),
    ('api-service-account',                    'KUBERNETES', 'ServiceAccount',  'PROD'),
    ('reused-api-7c4b',                        'KUBERNETES', 'Pod',             'PROD'),
    ('reused-assets',                          'AWS',        'S3 Bucket',       'PROD'),
    ('ci-legacy-user',                         'AWS',        'IAM User',        'DEV'),
    ('reused-chat',                            'KUBERNETES', 'Deployment',      'DEV'),
    ('logssey/reused-api:demo',                'AWS',        'Container Image', 'PROD');

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


-- 키 샘플 5개 (Notion PAT. Notion Admin API 응답 형식을 본뜬 가상 데이터)
-- 키 원문은 넣지 않는다 (ADR-D009). Notion은 이번 단계에서 assets에 넣지 않으므로 asset_id는 비운다.
-- 시각은 now() 기준이라 서버를 켤 때마다 판단 결과(정상·LOW·MEDIUM·HIGH·폐기)가 그대로 유지된다.
INSERT INTO credentials
    (issuer, credential_type, classification, display_name, external_id, owner, owner_team, purpose,
     status, source, issued_at, expiry_policy, expires_at, last_used_at, last_collected_at)
VALUES
    -- 정상: 탐지 없음
    ('NOTION', 'NOTION_PAT', 'SECRET', 'deploy-bot',    'sample-pat-0001', 'Team Member A', 'Platform', '배포 결과 기록',
     'ACTIVE',  'API', now() - interval '120 days', 'FIXED', now() + interval '90 days', now() - interval '1 day',   now()),
    -- 만료 임박(5일 뒤): LOW
    ('NOTION', 'NOTION_PAT', 'SECRET', 'notion-sync',   'sample-pat-0002', 'Team Member B', 'Backend',  '회의록 동기화',
     'ACTIVE',  'API', now() - interval '360 days', 'FIXED', now() + interval '5 days',  now() - interval '1 day',   now()),
    -- 60일 미사용: MEDIUM
    ('NOTION', 'NOTION_PAT', 'SECRET', 'old-script',    'sample-pat-0003', 'Team Member A', 'Platform', '일회성 데이터 이전',
     'ACTIVE',  'API', now() - interval '200 days', 'FIXED', now() + interval '90 days', now() - interval '60 days', now()),
    -- 만료일 없음: HIGH
    ('NOTION', 'NOTION_PAT', 'SECRET', 'legacy-export', 'sample-pat-0004', 'Team Member C', 'AppSec',   '문서 내보내기',
     'ACTIVE',  'API', now() - interval '30 days',  'NEVER', NULL,                       now() - interval '1 day',   now()),
    -- 폐기됨: 탐지 없음
    ('NOTION', 'NOTION_PAT', 'SECRET', 'revoked-tool',  'sample-pat-0005', 'Team Member B', 'Backend',  '테스트 연동',
     'REVOKED', 'API', now() - interval '150 days', 'FIXED', now() + interval '30 days', now() - interval '40 days', now());

-- 키 관련 탐지 이벤트는 여기서 넣지 않는다.
-- 서버가 이 파일을 실행한 뒤 CredentialRiskEventService가 위 키를 판단해 자동으로 만든다.
