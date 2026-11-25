-- 시크릿 결과 내보내기(SARIF·Logssey JSON·Gitleaks JSON) 감사 이벤트.
-- 기존 허용 값은 그대로 두고 SECRETS_EXPORTED 하나만 추가한다 (V51과 같은 방식).
DO $$ DECLARE prior TEXT; BEGIN
 SELECT pg_get_expr(conbin,conrelid) INTO prior FROM pg_constraint
 WHERE conrelid='secret_audit_events'::regclass AND conname='ck_secret_audit_event_type';
 ALTER TABLE secret_audit_events DROP CONSTRAINT ck_secret_audit_event_type;
 EXECUTE 'ALTER TABLE secret_audit_events ADD CONSTRAINT ck_secret_audit_event_type CHECK (('||prior||') OR event_type IN (''SECRETS_EXPORTED''))';
END $$;
