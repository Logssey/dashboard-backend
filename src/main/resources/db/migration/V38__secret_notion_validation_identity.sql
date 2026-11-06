-- Notion authentication observations use the existing validation history and identity model.
-- V36's _check enforces expires_at > observed_at. Only _check1 binds the provider.
ALTER TABLE secret_credential_identities
 DROP CONSTRAINT secret_credential_identities_provider_check,
 DROP CONSTRAINT secret_credential_identities_principal_type_check,
 DROP CONSTRAINT secret_credential_identities_check1;

ALTER TABLE secret_credential_identities
 ADD CONSTRAINT ck_secret_identity_provider CHECK(provider IN('AWS','GITHUB','NOTION')),
 ADD CONSTRAINT ck_secret_identity_principal_type CHECK(
  principal_type IN('IAM_USER','ASSUMED_ROLE','ROOT','GITHUB_USER','NOTION_BOT','UNKNOWN')),
 ADD CONSTRAINT ck_secret_identity_provider_binding CHECK(
  (provider='AWS' AND account_ref IS NOT NULL AND principal_ref ~ '^arn:aws(-[a-z]+)?:') OR
  (provider='GITHUB' AND account_ref IS NULL AND principal_type='GITHUB_USER'
   AND principal_ref ~ '^github-user:[1-9][0-9]*$') OR
  (provider='NOTION' AND account_ref IS NULL AND principal_type='NOTION_BOT'
   AND principal_id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
   AND principal_ref='notion-bot:'||principal_id)),
 ADD CONSTRAINT ck_secret_notion_identity_claims CHECK(provider<>'NOTION' OR (
  safe_claims ? 'schemaVersion' AND safe_claims->'schemaVersion'='1'::jsonb
  AND safe_claims-ARRAY['schemaVersion','workspaceRef','ownerType']='{}'::jsonb
  AND (NOT safe_claims ? 'workspaceRef' OR (
   jsonb_typeof(safe_claims->'workspaceRef')='string'
   AND safe_claims->>'workspaceRef' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'))
  AND (NOT safe_claims ? 'ownerType' OR (
   jsonb_typeof(safe_claims->'ownerType')='string'
   AND safe_claims->>'ownerType' IN('user','workspace')))));

CREATE OR REPLACE FUNCTION secret_identity_guard() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'IDENTITY_IMMUTABLE' USING ERRCODE='23514';END IF;
 IF NOT EXISTS(SELECT 1 FROM secret_current_validation_attempts a JOIN secret_occurrences o USING(occurrence_id)
  JOIN secret_credential_sets k ON k.credential_set_id=o.credential_set_id
  WHERE a.attempt_id=NEW.validation_attempt_id AND a.occurrence_id=NEW.occurrence_id
   AND a.credential_set_id=NEW.credential_set_id AND a.credential_revision=NEW.credential_revision
   AND a.scope_revision=NEW.scope_revision AND a.result='VALID' AND a.provider_checked_at IS NOT NULL
   AND k.issuer=NEW.provider
   AND (NEW.provider<>'NOTION' OR (
    k.credential_type='NOTION_CONNECTION_TOKEN' AND a.validator_id='NOTION_GET_SELF'
    AND a.validator_version='1' AND a.endpoint_class='NOTION_SELF' AND a.reason_code='AUTHENTICATED'
    AND NEW.observed_at=a.provider_checked_at)))
 THEN RAISE EXCEPTION 'IDENTITY_VALIDATION_PARENT' USING ERRCODE='23514';END IF;
 RETURN NEW;END $$;
