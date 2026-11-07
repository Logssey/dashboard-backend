-- Operator template. Run only against an approved environment after V41.
-- psql ... -v occurrence_id=12 -v collector_scope_id=3 -v approved_user_id=1 -v region=ap-northeast-2 -f register-usage-target.sql
-- Region is an explicit additional approval. The collector scope must already permit IAM key metadata.
-- Registration enables manual lookup; recurring lookup remains OFF until separately approved.
BEGIN;
INSERT INTO secret_usage_targets(occurrence_id,collector_connection_id,collector_scope_id,account_ref,region,
 credential_revision,scope_revision,source_scope_version,collector_scope_version,collector_scope_revision,
 collector_auth_ref,collector_approved_ref,approved_by_user_id,enabled,schedule_enabled)
SELECT o.occurrence_id,cc.connection_id,cs.scope_id,substring(cs.approved_ref from '^aws://([0-9]{12})/global/iam/access-keys$'), :'region',
 k.credential_revision,s.revision,c.scope_version,cc.scope_version,cs.revision,cc.auth_ref,cs.approved_ref,:'approved_user_id'::bigint,true,false
FROM secret_occurrences o JOIN secret_credential_sets k USING(credential_set_id)
JOIN secret_connection_scopes s ON s.scope_id=o.scope_id JOIN secret_connections c ON c.connection_id=o.connection_id
JOIN secret_connection_scopes cs ON cs.scope_id=:'collector_scope_id'::bigint
JOIN secret_connections cc ON cc.connection_id=cs.connection_id
WHERE o.occurrence_id=:'occurrence_id'::bigint AND k.issuer='AWS'
 AND k.credential_type IN('AWS_ACCESS_KEY_PAIR','AWS_IAM_ACCESS_KEY','AWS_TEMPORARY_CREDENTIALS')
 AND c.status='ACTIVE' AND s.enabled AND cc.provider='AWS' AND cc.status='ACTIVE' AND cs.enabled
 AND cs.content_type='IAM_ACCESS_KEY_METADATA' AND cs.approved_ref ~ '^aws://[0-9]{12}/global/iam/access-keys$'
 AND (cs.history_limit IS NULL OR cs.history_limit='CURRENT_STATE_ONLY')
 AND EXISTS(SELECT 1 FROM secret_role_grants g WHERE g.user_id=:'approved_user_id'::bigint AND g.revoked_at IS NULL
  AND g.role='SECURITY' AND(g.connection_id IS NULL OR g.connection_id=o.connection_id))
 AND EXISTS(SELECT 1 FROM secret_role_grants g WHERE g.user_id=:'approved_user_id'::bigint AND g.revoked_at IS NULL
  AND g.role IN('SECURITY','OPERATIONS') AND(g.connection_id IS NULL OR g.connection_id=cc.connection_id))
ON CONFLICT(occurrence_id,collector_connection_id,account_ref,region) DO UPDATE SET
 collector_scope_id=excluded.collector_scope_id,credential_revision=excluded.credential_revision,
 scope_revision=excluded.scope_revision,source_scope_version=excluded.source_scope_version,
 collector_scope_version=excluded.collector_scope_version,collector_scope_revision=excluded.collector_scope_revision,
 collector_auth_ref=excluded.collector_auth_ref,collector_approved_ref=excluded.collector_approved_ref,
 approved_by_user_id=excluded.approved_by_user_id,approved_at=clock_timestamp(),revision=secret_usage_targets.revision+1,
 enabled=true,schedule_enabled=false
RETURNING target_id,region,enabled,schedule_enabled;
COMMIT;
