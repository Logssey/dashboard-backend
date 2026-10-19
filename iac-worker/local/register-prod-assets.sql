-- 로컬 개발용: prod 환경의 IaC 대상 레포와 데이터 등급 자산 (IaC 보안 rule-spec "데이터 등급").
-- 환경마다 값이 달라 마이그레이션에 넣지 않는다. 시크릿 ARN 은 2026-10-13 수집 그래프 기준.
-- 실행: psql "$DB_URL" -f iac-worker/local/register-prod-assets.sql (여러 번 실행해도 같음)

INSERT INTO iac_repos (full_name, default_branch, environment)
VALUES ('Logssey/infrastructure', 'main', 'PROD')
ON CONFLICT (full_name) DO NOTHING;

INSERT INTO iac_data_assets (arn, kind, tier) VALUES
    ('arn:aws:rds:ap-northeast-1:794386801311:db:logssey-prod-rds', 'RDS', 1),
    ('arn:aws:s3:::logssey-prod-s3-tfstate', 'TFSTATE', 1),
    ('arn:aws:secretsmanager:ap-northeast-1:794386801311:secret:logssey/prod/grafana-TqYT6P', 'SECRET', 1),
    ('arn:aws:secretsmanager:ap-northeast-1:794386801311:secret:logssey/prod/grafana-oauth-cE8mj7', 'SECRET', 1),
    ('arn:aws:secretsmanager:ap-northeast-1:794386801311:secret:rds!db-c78baf92-e022-4c45-91d8-2a27265e7c51-ZMZtyJ', 'SECRET', 1),
    ('arn:aws:secretsmanager:ap-northeast-1:794386801311:secret:reused-reused-temp-pentest-2-secret-8F12M7IOC-u8QR3c', 'SECRET', 1),
    ('arn:aws:secretsmanager:ap-northeast-1:794386801311:secret:reused-reused-temp-pentest-secret-8F12KM328-wfwDUc', 'SECRET', 1),
    ('arn:aws:secretsmanager:ap-northeast-1:794386801311:secret:reused/prod/api-ONfjwj', 'SECRET', 1),
    ('arn:aws:secretsmanager:ap-northeast-1:794386801311:secret:reused/prod/chat-dvg9mY', 'SECRET', 1),
    ('arn:aws:s3:::logssey-prod-s3-images', 'S3', 2),
    ('arn:aws:s3:::logssey-prod-loki-chunks', 'S3', 2),
    ('arn:aws:s3:::logssey-prod-loki-ruler', 'S3', 2)
ON CONFLICT (arn) DO UPDATE SET kind = EXCLUDED.kind, tier = EXCLUDED.tier, updated_at = now();
