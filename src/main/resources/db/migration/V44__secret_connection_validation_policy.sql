-- Explicit connection policy replaces the repository-name authentication guard.
-- Existing enabled connections retain their registered issuer behavior. Management commands
-- always provide the complete allowed issuer selection and never enable a scope implicitly.
ALTER TABLE secret_connections
 ADD COLUMN validation_allowed_issuers TEXT[] NOT NULL DEFAULT ARRAY['AWS','GITHUB','NOTION']::text[],
 ADD CONSTRAINT ck_secret_validation_issuers CHECK(
   cardinality(validation_allowed_issuers)<=3
   AND (cardinality(validation_allowed_issuers)=0 OR array_ndims(validation_allowed_issuers)=1)
   AND array_position(validation_allowed_issuers,NULL) IS NULL
   AND validation_allowed_issuers <@ ARRAY['AWS','GITHUB','NOTION']::text[]
   AND (NOT validation_enabled OR cardinality(validation_allowed_issuers)>0));

CREATE OR REPLACE VIEW secret_validation_context AS
 SELECT o.occurrence_id,o.credential_set_id,o.connection_id,o.scope_id,
  k.issuer,k.credential_type,k.component_state,k.credential_revision,k.fingerprint_key_version,c.provider AS source_provider,
  o.exposure_assessment_version AS occurrence_revision,s.revision AS scope_revision,
  s.validation_approval_revision,c.validation_revision,c.scope_version,c.status AS connection_status,
  s.enabled AS scope_enabled,c.validation_enabled,s.validation_approved,
  (s.synthetic_fixture OR EXISTS(SELECT 1 FROM secret_current_fixture_attestations fa WHERE fa.credential_set_id=k.credential_set_id AND fa.scope_id=s.scope_id)) AS synthetic_fixture,
  c.validation_profile_version AS connection_profile,s.validation_profile_version AS scope_profile,
  COALESCE(a.action_id,0) AS action_id,a.performed_at AS action_performed_at,
  encode(sha256(convert_to(concat_ws(':',o.occurrence_id,k.credential_set_id,k.credential_revision,k.fingerprint_key_version,
   o.exposure_assessment_version,s.revision,s.validation_approval_revision,c.validation_revision,c.scope_version,
   c.status,s.enabled,c.validation_enabled,s.validation_approved,c.validation_profile_version,s.validation_profile_version,
   s.synthetic_fixture,c.validation_allowed_issuers::text,
   EXISTS(SELECT 1 FROM secret_current_fixture_attestations fa WHERE fa.credential_set_id=k.credential_set_id AND fa.scope_id=s.scope_id),
   COALESCE(a.action_id,0),a.performed_at),'UTF8')),'hex') AS context_version,
  false AS source_guard_blocked,
  c.validation_allowed_issuers,(k.issuer=ANY(c.validation_allowed_issuers)) AS validation_issuer_allowed
 FROM secret_occurrences o JOIN secret_credential_sets k USING(credential_set_id)
 JOIN secret_connection_scopes s ON s.scope_id=o.scope_id JOIN secret_connections c ON c.connection_id=o.connection_id
 LEFT JOIN LATERAL(SELECT action_id,performed_at FROM secret_action_records WHERE occurrence_id=o.occurrence_id ORDER BY performed_at DESC,action_id DESC LIMIT 1) a ON true;

CREATE OR REPLACE VIEW secret_current_validation_attempts AS
 SELECT a.* FROM secret_validation_attempts a JOIN secret_validation_context v ON v.occurrence_id=a.occurrence_id
 WHERE a.evidence_version=1 AND a.attempt_state='COMPLETED' AND a.current_eligible
 AND a.credential_set_id=v.credential_set_id AND a.credential_revision=v.credential_revision AND a.scope_id=v.scope_id
 AND a.scope_revision=v.scope_revision AND a.validation_revision=v.validation_revision AND a.validation_approval_revision=v.validation_approval_revision
 AND (a.result='UNCHECKED' OR (v.connection_status='ACTIVE' AND v.scope_enabled AND v.validation_enabled AND v.validation_approved
  AND a.validation_profile_version=v.connection_profile AND v.connection_profile=v.scope_profile AND NOT v.synthetic_fixture AND NOT v.source_guard_blocked AND v.validation_issuer_allowed));

CREATE OR REPLACE FUNCTION secret_execution_safe_reason(value TEXT) RETURNS TEXT LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN value IN(
 'OPERATION_FAILED','LEASE_EXPIRED','PROCESSOR_FAILURE','INCOMPLETE_RUN','SOURCE_UNAVAILABLE',
 'SOURCE_ACCESS_DENIED','SOURCE_RATE_LIMITED','DETECTOR_TEMPORARY','VALIDATOR_TEMPORARY',
 'VALIDATION_ATTEMPT_FAILED','VALIDATION_INCONCLUSIVE','NOT_APPLICABLE_METADATA','NO_OBJECTS','NO_CANDIDATES',
 'NO_SUPPORTED_VALIDATOR','VALIDATION_DISABLED','SYNTHETIC_FIXTURE','AUTH_REJECTED','AUTH_ACCEPTED',
 'AUTHENTICATION_FAILED','NETWORK_ERROR','TIMEOUT','RATE_LIMITED','ACCESS_DENIED','MALFORMED_RESPONSE',
 'SOURCE_GUARD_BLOCKED','VALIDATOR_DISABLED','UNSUPPORTED_TYPE','INCOMPLETE_CREDENTIAL','CONFIGURATION_ERROR',
 'RETRY_BUDGET_EXHAUSTED','RATE_BUDGET_EXHAUSTED','APPROVAL_CHANGED','CANCELLED',
 'AUTHENTICATION_REJECTED','INVALID_ACCESS_KEY','SIGNATURE_AMBIGUOUS','EXPIRED_SESSION','INCOMPLETE_PAIR','MISSING_SESSION_TOKEN','ACCESS_AMBIGUOUS','CLIENT_FAILURE','NOT_APPROVED','CREDENTIAL_MISMATCH',
 'DISABLED','UNSUPPORTED','AUTHENTICATED','AUTH_REJECTED','INVALID_CLIENT_TOKEN','INVALID_SIGNATURE','EXPIRED','ACCESS_LIMITED','PROVIDER_UNAVAILABLE','NETWORK_FAILURE','UNEXPECTED_RESPONSE','INCOMPLETE','SOURCE_GUARD_BLOCKED',
 'GITHUB_AUTHENTICATED','GITHUB_BAD_CREDENTIALS','GITHUB_UNAUTHORIZED','GITHUB_FORBIDDEN','GITHUB_RATE_LIMITED',
 'GITHUB_PROVIDER_UNAVAILABLE','GITHUB_NETWORK_ERROR','GITHUB_TIMEOUT','GITHUB_MALFORMED_RESPONSE',
 'NOTION_AUTHENTICATED','NOTION_UNAUTHORIZED','NOTION_RESTRICTED_RESOURCE','NOTION_RATE_LIMITED','NOTION_TIMEOUT',
 'NOTION_SOURCE_UNAVAILABLE','NOTION_MALFORMED_RESPONSE','AWS_AUTHENTICATED','AWS_INVALID_CLIENT_TOKEN_ID',
 'AWS_SIGNATURE_DOES_NOT_MATCH','AWS_EXPIRED_TOKEN','AWS_ACCESS_DENIED','AWS_THROTTLED','AWS_UNAVAILABLE',
 'GITHUB_ACCESS_DENIED','GITHUB_SOURCE_UNAVAILABLE','GITHUB_TREE_LIMIT','GITHUB_FILE_LIMIT','GITHUB_TREE_TRUNCATED',
 'GITHUB_FILE_TOO_LARGE','GITHUB_TOTAL_BYTES_LIMIT','GITHUB_BINARY_FILE','GITHUB_UNSUPPORTED_OBJECT',
 'AWS_CONTENT_READ_DISABLED','AWS_CONTENT_ACCESS_DENIED','AWS_CONTENT_NOT_FOUND','AWS_CONTENT_SOURCE_UNAVAILABLE',
 'AWS_CONTENT_OBJECT_TOO_LARGE','AWS_CONTENT_NON_TEXT','AWS_ROOT_ACCESS_KEYS_PRESENT','AWS_ROOT_KEY_COVERAGE_UNKNOWN',
 'NOTION_NOT_FOUND','NOTION_ACCESS_DENIED','NOTION_CONTENT_CHANGED','NOTION_UNSUPPORTED_BLOCK','NOTION_BLOCK_LIMIT',
 'NOTION_DEPTH_LIMIT','NOTION_TEXT_LIMIT','NOTION_REQUEST_LIMIT','NOTION_CURSOR_LOOP','NOTION_COLLECTION_DISABLED',
 'DETECTOR_INPUT_TOO_LARGE','DETECTOR_OUTPUT_TOO_LARGE','DETECTOR_TOOL_UNAVAILABLE','DETECTOR_TOOL_TIMEOUT',
 'DETECTOR_TOOL_EXIT','DETECTOR_INVALID_REPORT','DETECTOR_NORMALIZATION_INCOMPLETE','RESULT_PERSISTENCE_FAILED',
 'VALIDATION_DEADLINE_EXCEEDED','STAGE_NOT_OBSERVED','VALIDATOR_NOT_ALLOWED') THEN value
 WHEN value IS NULL THEN NULL ELSE 'OPERATION_FAILED' END
$$;

CREATE OR REPLACE FUNCTION secret_record_scope_evidence(target BIGINT, validation_failed BOOLEAN)
RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    s secret_run_scopes%ROWTYPE;
    t secret_tool_runs%ROWTYPE;
    a RECORD;
    candidates BIGINT;
BEGIN
    SELECT * INTO STRICT s FROM secret_run_scopes WHERE run_scope_id=target;
    IF s.evidence_version IS NULL THEN RETURN; END IF;
    IF right(s.snapshot_content_type,9)='_METADATA' THEN
        UPDATE secret_run_scopes SET detection_stage_status='SKIPPED', detection_reason_code='NOT_APPLICABLE_METADATA',
            validation_stage_status='SKIPPED', validation_reason_code='NOT_APPLICABLE_METADATA', validation_required=false
        WHERE run_scope_id=target;
        RETURN;
    END IF;
    SELECT * INTO t FROM secret_tool_runs WHERE run_scope_id=target AND engine='GITLEAKS';
    SELECT count(*) INTO candidates FROM secret_findings WHERE tool_run_id=t.tool_run_id;
    SELECT count(*) AS total,
        count(*) FILTER(WHERE v.result IN ('VALID','INVALID')) AS checked,
        count(*) FILTER(WHERE v.result='UNKNOWN' OR v.result='UNCHECKED' AND v.reason_code NOT IN ('DISABLED','SYNTHETIC_FIXTURE','SOURCE_GUARD_BLOCKED','VALIDATOR_NOT_ALLOWED')) AS incomplete,
        count(*) FILTER(WHERE v.reason_code='DISABLED') AS disabled,
        count(*) FILTER(WHERE v.reason_code='SYNTHETIC_FIXTURE') AS fixture,
        count(*) FILTER(WHERE v.reason_code='SOURCE_GUARD_BLOCKED') AS guarded,
        count(*) FILTER(WHERE v.reason_code='VALIDATOR_NOT_ALLOWED') AS disallowed
    INTO a FROM secret_validation_attempts v
    WHERE v.run_id=s.run_id AND v.attempt_state='COMPLETED' AND
        (v.evidence_version=0 OR v.scope_id=s.scope_id) AND EXISTS (
        SELECT 1 FROM secret_findings f JOIN secret_occurrences o ON o.occurrence_id=f.occurrence_id
        WHERE f.tool_run_id=t.tool_run_id AND o.credential_set_id=v.credential_set_id);
    UPDATE secret_run_scopes SET
        detection_stage_status=COALESCE(t.status, CASE WHEN collection_status='SUCCEEDED' AND object_count=0 THEN 'SKIPPED' END),
        detection_reason_code=CASE WHEN t.tool_run_id IS NOT NULL THEN t.failure_code
             WHEN collection_status='SUCCEEDED' AND object_count=0 THEN 'NO_OBJECTS' ELSE 'DETECTION_NOT_RUN' END,
        validation_stage_status=CASE WHEN validation_failed OR a.incomplete>0 THEN 'PARTIAL'
             WHEN a.checked>0 THEN 'SUCCEEDED' ELSE 'SKIPPED' END,
        validation_reason_code=CASE WHEN validation_failed THEN 'VALIDATION_ATTEMPT_FAILED'
             WHEN a.incomplete>0 THEN 'VALIDATION_INCONCLUSIVE' WHEN a.checked>0 THEN NULL
             WHEN a.disabled>0 THEN 'VALIDATION_DISABLED' WHEN a.fixture>0 THEN 'SYNTHETIC_FIXTURE'
             WHEN a.guarded>0 THEN 'SOURCE_GUARD_BLOCKED'
             WHEN a.disallowed>0 THEN 'VALIDATOR_NOT_ALLOWED'
             WHEN candidates=0 THEN 'NO_CANDIDATES' ELSE 'NO_SUPPORTED_VALIDATOR' END,
        validation_required=(validation_failed OR a.checked>0 OR a.incomplete>0)
    WHERE run_scope_id=target;
END $$;
