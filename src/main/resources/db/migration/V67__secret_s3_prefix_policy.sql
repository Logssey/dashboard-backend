-- Match approved storage policies to each observed object within an approved S3 prefix.
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
              OR (basis.content_type='AWS_S3_OBJECT_CONTENT'
                  AND basis.history_limit='CURRENT_VALUE_ONLY' AND r.path_match='SCOPE'
                  AND basis.approved_ref ~ '^aws://[0-9]{12}/[a-z0-9-]+/s3/prefix/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]/([^/?#%*]|%[0-9A-Fa-f]{2})+%2F$'
                  AND starts_with(basis.source_object_ref,'aws-content-scope:' || basis.scope_id::text || ':' || split_part(basis.approved_ref,'/',8))
                  AND length(basis.source_object_ref)>length('aws-content-scope:' || basis.scope_id::text || ':' || split_part(basis.approved_ref,'/',8))
                  AND basis.source_object_ref !~ '%2F$')
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
