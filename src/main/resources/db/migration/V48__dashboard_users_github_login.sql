-- GitHub 로그인 (ADR-D010). GitHub로 들어온 사람은 GitHub 계정 ID로 찾는다.
-- 비밀번호 계정(비상용 admin)은 github_id 가 NULL 이다.
ALTER TABLE dashboard_users ADD COLUMN github_id BIGINT;
ALTER TABLE dashboard_users ADD CONSTRAINT uq_dashboard_users_github_id UNIQUE (github_id);
