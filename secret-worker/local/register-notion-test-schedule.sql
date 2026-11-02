-- Explicit local opt-in, not Flyway seed data. Contains references only, never the Notion token.
-- Replace the page id below with the id of ONE test page shared with the read-only collector
-- (the 32 hex digits at the end of the page URL). Never register a page that holds real keys.
BEGIN;
SELECT pg_advisory_xact_lock(5282127);

INSERT INTO secret_connections (provider, display_name, auth_ref, status, scope_version, next_due_at)
SELECT 'NOTION', 'Notion test page (local)', 'notion-connection:local-secret-collector', 'ACTIVE', 1,
       CURRENT_TIMESTAMP
WHERE NOT EXISTS (
    SELECT 1 FROM secret_connections
    WHERE provider = 'NOTION' AND auth_ref = 'notion-connection:local-secret-collector'
);

INSERT INTO secret_connection_scopes
    (connection_id, scope_key, revision, content_type, approved_ref, history_limit, enabled)
SELECT connection_id, 'notion:page:00000000000000000000000000000000', 1,
       'NOTION_PAGE_CONTENT', 'notion://pages/00000000000000000000000000000000',
       'CURRENT_VERSION_ONLY', true
FROM secret_connections c
WHERE provider = 'NOTION' AND auth_ref = 'notion-connection:local-secret-collector'
  AND NOT EXISTS (SELECT 1 FROM secret_connection_scopes s WHERE s.connection_id = c.connection_id);
COMMIT;
