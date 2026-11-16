ALTER TABLE secret_connections
 ADD COLUMN source_credential_version BIGINT NOT NULL DEFAULT 0 CHECK(source_credential_version>=0),
 ADD COLUMN source_credential_enabled BOOLEAN NOT NULL DEFAULT false,
 ADD COLUMN credential_deletion_pending BOOLEAN NOT NULL DEFAULT false,
 ADD COLUMN credential_recovery_until TIMESTAMPTZ;

-- The private key exists only in Secrets Manager. The exact remote version is pinned here.
CREATE TABLE secret_source_credential_versions (
 connection_id BIGINT NOT NULL REFERENCES secret_connections,
 version BIGINT NOT NULL CHECK(version>0),
 secret_name VARCHAR(512) NOT NULL,
 secret_version_id VARCHAR(64) NOT NULL,
 app_id BIGINT NOT NULL CHECK(app_id>0),
 installation_id BIGINT NOT NULL CHECK(installation_id>0),
 created_by_user_id BIGINT NOT NULL REFERENCES dashboard_users,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(connection_id,version)
);
CREATE FUNCTION secret_source_credential_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'SOURCE_CREDENTIAL_REFERENCE_IMMUTABLE' USING ERRCODE='23514'; END $$;
CREATE TRIGGER trg_secret_source_credential_immutable BEFORE UPDATE OR DELETE ON secret_source_credential_versions
 FOR EACH ROW EXECUTE FUNCTION secret_source_credential_immutable();

DO $$ DECLARE prior TEXT; BEGIN
 SELECT pg_get_expr(conbin,conrelid) INTO prior FROM pg_constraint
 WHERE conrelid='secret_audit_events'::regclass AND conname='ck_secret_audit_event_type';
 ALTER TABLE secret_audit_events DROP CONSTRAINT ck_secret_audit_event_type;
 EXECUTE 'ALTER TABLE secret_audit_events ADD CONSTRAINT ck_secret_audit_event_type CHECK (('||prior||') OR event_type IN (''SOURCE_CONNECTION_CREATED'',''SOURCE_CONNECTION_CHANGED'',''SOURCE_CONNECTION_TARGETS_CHANGED'',''SOURCE_CREDENTIAL_DISABLED''))';
END $$;

-- Decode URI coordinates once for comparisons against the worker's original GitHub paths.
-- A literal '+' stays '+'. Invalid percent sequences cannot become policy evidence.
CREATE FUNCTION secret_github_decode_part(value TEXT) RETURNS TEXT
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE bytes BYTEA := ''::bytea; pos INTEGER := 1; pair TEXT;
BEGIN
 WHILE pos<=length(value) LOOP
  IF substr(value,pos,1)='%' THEN
   pair:=substr(value,pos+1,2);
   IF length(pair)<>2 OR pair !~ '^[0-9A-Fa-f]{2}$' THEN RETURN NULL; END IF;
   bytes:=bytes||decode(pair,'hex');pos:=pos+3;
  ELSE bytes:=bytes||convert_to(substr(value,pos,1),'UTF8');pos:=pos+1;
  END IF;
 END LOOP;
 RETURN convert_from(bytes,'UTF8');
EXCEPTION WHEN OTHERS THEN RETURN NULL;
END $$;
CREATE FUNCTION secret_github_scope_parts(reference TEXT) RETURNS TEXT[]
LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE parts TEXT[];
BEGIN
 parts:=regexp_match(reference,'^github://([A-Za-z0-9-]+)/([A-Za-z0-9_.-]+)/([^/?#]+)/([^?#]*)$');
 IF parts IS NULL THEN RETURN NULL; END IF;
 parts[3]:=secret_github_decode_part(parts[3]);parts[4]:=secret_github_decode_part(parts[4]);
 IF parts[3] IS NULL OR parts[4] IS NULL THEN RETURN NULL; END IF;
 RETURN parts;
END $$;

-- Repository-root scopes use an empty prefix and preserve existing policy rules.
CREATE OR REPLACE VIEW secret_occurrence_policy_results AS
WITH scope_basis AS (
    SELECT o.occurrence_id,o.scope_id,o.source_object_ref,o.exposure_status,
           o.policy_assessed_binding_id,o.policy_assessed_origin_version,o.policy_recheck_required,
           s.connection_id,s.revision,s.response_origin,s.response_origin_version,s.enabled,
           s.content_type,s.history_limit,s.approved_ref,
           md5(jsonb_build_array(s.content_type,s.approved_ref,s.history_limit)::text) AS fingerprint,
           secret_github_scope_parts(s.approved_ref) AS github,
           b.binding_id,b.scope_revision AS bound_revision,b.scope_origin_version AS bound_origin_version,
           b.scope_fingerprint AS bound_fingerprint,b.policy_id,b.policy_version,
           p.status,p.valid_from,p.valid_until
    FROM secret_occurrences o
    JOIN secret_connection_scopes s ON s.scope_id=o.scope_id
    LEFT JOIN secret_scope_policy_bindings b ON b.scope_id=s.scope_id
        AND b.effective_until IS NULL AND b.effective_from <= now()
    LEFT JOIN secret_storage_policies p ON p.policy_id=b.policy_id AND p.version=b.policy_version
), matched AS (
    SELECT basis.*,
        COALESCE(rules.allow_count,0) AS allow_count,COALESCE(rules.deny_count,0) AS deny_count
    FROM scope_basis basis
    LEFT JOIN LATERAL (
        SELECT COUNT(*) FILTER (WHERE r.effect='ALLOW') AS allow_count,
               COUNT(*) FILTER (WHERE r.effect='DENY') AS deny_count
        FROM secret_storage_policy_rules r
        WHERE r.policy_id=basis.policy_id AND r.policy_version=basis.policy_version
          AND r.connection_id=basis.connection_id AND r.scope_id=basis.scope_id
          AND r.scope_revision=basis.revision AND r.scope_fingerprint=basis.fingerprint
          AND r.content_type=basis.content_type
          AND (
              (basis.content_type='GITHUB_REPOSITORY_FILES' AND basis.history_limit='CURRENT_COMMIT_ONLY'
               AND basis.github IS NOT NULL
               AND starts_with(basis.source_object_ref,basis.github[1] || '/' || basis.github[2] || '/' || basis.github[4])
               AND basis.source_object_ref !~ '(^|/)\.\.(/|$)'
               AND (r.path_match='SCOPE' OR
                    (r.branch_condition=basis.github[3] AND (
                        (r.path_match='EXACT' AND basis.source_object_ref=basis.github[1] || '/' || basis.github[2] || '/' || r.protected_path_condition)
                        OR (r.path_match='PREFIX' AND starts_with(basis.source_object_ref,basis.github[1] || '/' || basis.github[2] || '/' || r.protected_path_condition))
                    ))))
              OR (basis.content_type IN ('AWS_SECRETS_MANAGER_VALUE','AWS_SSM_PARAMETER_VALUE','AWS_S3_OBJECT_CONTENT')
                  AND basis.history_limit='CURRENT_VALUE_ONLY' AND r.path_match='SCOPE'
                  AND basis.approved_ref ~ '^aws://[0-9]{12}/[a-z0-9-]+/(secrets-manager/secret|ssm/parameter|s3/object)/[^?#*]+$'
                  AND basis.source_object_ref='aws-content-scope:' || basis.scope_id::text)
              OR (basis.content_type='NOTION_PAGE_CONTENT' AND basis.history_limit='CURRENT_VERSION_ONLY'
                  AND r.path_match='SCOPE'
                  AND basis.approved_ref ~ '^notion://pages/([0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$'
                  AND basis.source_object_ref ~ '^notion/pages/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/(title|blocks/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$'
                  AND replace(split_part(basis.approved_ref,'/',4),'-','')
                      =replace(split_part(basis.source_object_ref,'/',3),'-',''))
          )
    ) rules ON true
), evaluated AS (
    SELECT matched.*,
       CASE WHEN content_type IN ('IAM_ACCESS_KEY_METADATA','AWS_SECRETS_MANAGER_METADATA','AWS_SSM_PARAMETER_METADATA','AWS_S3_BUCKET_METADATA') THEN 'METADATA_NOT_APPLICABLE'
            WHEN binding_id IS NULL THEN 'NO_ACTIVE_BINDING'
            WHEN NOT enabled OR (response_origin='UNCLASSIFIED' AND NOT EXISTS(SELECT 1 FROM secret_scope_origin_decisions approved
              WHERE approved.scope_id=matched.scope_id AND approved.version=matched.response_origin_version
                AND approved.decision='APPROVED')) THEN 'SCOPE_NOT_APPROVED'
            WHEN bound_revision<>revision OR bound_origin_version<>response_origin_version OR bound_fingerprint<>fingerprint THEN 'SCOPE_CHANGED'
            WHEN status<>'ACTIVE' THEN 'POLICY_RETIRED'
            WHEN now()<valid_from THEN 'POLICY_NOT_YET_VALID'
            WHEN valid_until IS NOT NULL AND now()>=valid_until THEN 'POLICY_EXPIRED'
            WHEN allow_count>0 AND deny_count>0 THEN 'POLICY_CONFLICT'
            WHEN allow_count>0 THEN 'EXPLICIT_ALLOW'
            WHEN deny_count>0 THEN 'EXPLICIT_DENY'
            ELSE 'NO_MATCHING_RULE' END AS reason_code
    FROM matched
)
SELECT occurrence_id,scope_id,binding_id,policy_id,policy_version,reason_code,
       CASE reason_code WHEN 'EXPLICIT_ALLOW' THEN 'ALLOWED' WHEN 'EXPLICIT_DENY' THEN 'DENIED' ELSE 'UNKNOWN' END::varchar(10) AS policy_result,
       (policy_recheck_required OR (exposure_status<>'UNKNOWN' AND (
           policy_assessed_binding_id IS DISTINCT FROM binding_id
           OR policy_assessed_origin_version IS DISTINCT FROM response_origin_version
           OR (binding_id IS NOT NULL AND reason_code NOT IN ('EXPLICIT_ALLOW','EXPLICIT_DENY'))
       ))) AS requires_reassessment
FROM evaluated;

-- Configuration changes terminate every unfinished stage with the original causal reason.
CREATE OR REPLACE FUNCTION secret_execution_safe_reason(value TEXT) RETURNS TEXT LANGUAGE sql IMMUTABLE AS $$
 SELECT CASE WHEN value IN(
 'OPERATION_FAILED','LEASE_EXPIRED','PROCESSOR_FAILURE','INCOMPLETE_RUN','SOURCE_UNAVAILABLE','SOURCE_CONFIGURATION_CHANGED',
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
CREATE OR REPLACE FUNCTION secret_execution_run_terminal() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE j secret_jobs%ROWTYPE; stage_name TEXT; value TEXT; outcome TEXT; reason TEXT; total BIGINT; done BIGINT;
BEGIN
 IF NEW.result_status=OLD.result_status OR NEW.result_status NOT IN('SUCCEEDED','PARTIAL','FAILED','SKIPPED') THEN RETURN NEW; END IF;
 SELECT * INTO j FROM secret_jobs WHERE job_id=NEW.job_id;
 SELECT count(*),count(*) FILTER(WHERE collection_status IN('SUCCEEDED','PARTIAL','FAILED','SKIPPED')) INTO total,done
 FROM secret_run_scopes WHERE run_id=NEW.run_id;
 FOREACH stage_name IN ARRAY ARRAY['COLLECTION','DETECTION','VALIDATION','RESULT'] LOOP
  value:=CASE stage_name WHEN 'COLLECTION' THEN NEW.collection_status WHEN 'DETECTION' THEN NEW.detection_status
   WHEN 'VALIDATION' THEN NEW.validation_status ELSE NEW.result_status END;
  IF value NOT IN('SUCCEEDED','PARTIAL','FAILED','SKIPPED') THEN CONTINUE; END IF;
  outcome:=CASE value WHEN 'SUCCEEDED' THEN 'COMPLETED' ELSE value END;
  reason:=NEW.failure_code;
  IF value='SUCCEEDED' AND stage_name IN('COLLECTION','DETECTION','VALIDATION')
   AND NOT EXISTS(SELECT 1 FROM secret_run_execution_stage_facts f
    WHERE f.run_id=NEW.run_id AND f.attempt_no=j.attempt_no AND f.stage=stage_name AND f.started_at IS NOT NULL)
  THEN outcome:='SKIPPED';reason:='STAGE_NOT_OBSERVED'; END IF;
  IF value='SKIPPED' AND NEW.failure_code IS DISTINCT FROM 'SOURCE_CONFIGURATION_CHANGED' THEN
   SELECT CASE WHEN bool_and(right(snapshot_content_type,9)='_METADATA') THEN 'NOT_APPLICABLE_METADATA'
    WHEN stage_name='DETECTION' AND COALESCE(sum(object_count),0)=0 THEN 'NO_OBJECTS'
    ELSE min(CASE WHEN stage_name='VALIDATION' THEN validation_reason_code ELSE detection_reason_code END) END
    INTO reason FROM secret_run_scopes WHERE run_id=NEW.run_id;
  END IF;
  PERFORM secret_append_execution_event(NEW.run_id,NULL,j.attempt_no,j.lease_generation,stage_name,
   CASE WHEN stage_name='RESULT' THEN 'RUN_FINISHED' ELSE 'STAGE_SUMMARY' END,outcome,NULL,reason,
   CASE WHEN stage_name='COLLECTION' THEN done ELSE NULL END,CASE WHEN stage_name='COLLECTION' THEN total ELSE NULL END,
   NULL,'summary:'||j.attempt_no||':'||stage_name,true);
 END LOOP;
 RETURN NEW;
END $$;
