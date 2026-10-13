-- Explicit local opt-in, not Flyway seed data. Contains references only, no private key/token.
BEGIN;
SELECT pg_advisory_xact_lock(5282126);

INSERT INTO secret_connections (provider, display_name, auth_ref, status, scope_version, next_due_at)
SELECT 'GITHUB', 'GitHub fixtures (local)', 'github-app:local-secret-collector', 'ACTIVE', 1, CURRENT_TIMESTAMP
WHERE NOT EXISTS (
    SELECT 1 FROM secret_connections
    WHERE provider = 'GITHUB' AND auth_ref = 'github-app:local-secret-collector'
);

INSERT INTO secret_connection_scopes
    (connection_id, scope_key, revision, content_type, approved_ref, history_limit, enabled)
SELECT connection_id, 'github:Logssey/test-find-key:main:fixtures/', 1,
       'GITHUB_REPOSITORY_FILES', 'github://Logssey/test-find-key/main/fixtures/',
       'CURRENT_COMMIT_ONLY', true
FROM secret_connections c
WHERE provider = 'GITHUB' AND auth_ref = 'github-app:local-secret-collector'
  AND NOT EXISTS (SELECT 1 FROM secret_connection_scopes s WHERE s.connection_id = c.connection_id);
COMMIT;
