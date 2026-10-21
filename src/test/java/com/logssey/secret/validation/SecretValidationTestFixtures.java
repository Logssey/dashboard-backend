package com.logssey.secret.validation;

import java.time.OffsetDateTime;
import org.springframework.jdbc.core.JdbcTemplate;

/** Database-only provider observations with the same current-context fields as the real writer. */
public final class SecretValidationTestFixtures {
  private SecretValidationTestFixtures() {}

  public static long completed(
      JdbcTemplate jdbc,
      long occurrence,
      long job,
      long run,
      String result,
      String reason,
      OffsetDateTime requested,
      OffsetDateTime completed,
      OffsetDateTime checked) {
    var location =
        jdbc.queryForMap(
            "SELECT connection_id,scope_id FROM secret_occurrences WHERE occurrence_id=?",
            occurrence);
    long approver =
        jdbc.queryForObject(
            "SELECT min(user_id) FROM secret_role_grants WHERE role='SECURITY' AND revoked_at IS"
                + " NULL AND(connection_id IS NULL OR connection_id=?)",
            Long.class,
            location.get("connection_id"));
    jdbc.update(
        "UPDATE secret_connections SET"
            + " validation_enabled=true,validation_profile_version='credential-validation-v1' WHERE"
            + " connection_id=?",
        location.get("connection_id"));
    jdbc.update(
        "UPDATE secret_connection_scopes SET"
            + " validation_approved=true,validation_profile_version='credential-validation-v1',validation_approved_by_user_id=?,validation_approved_at=clock_timestamp()"
            + " WHERE scope_id=?",
        approver,
        location.get("scope_id"));
    var sources =
        jdbc.queryForList(
            "SELECT f.finding_id FROM secret_findings f JOIN secret_tool_runs t USING(tool_run_id)"
                + " JOIN secret_run_scopes rs USING(run_scope_id) WHERE f.occurrence_id=? AND"
                + " f.run_id=? AND rs.scope_id=? ORDER BY finding_id DESC LIMIT 1",
            occurrence,
            run,
            location.get("scope_id"));
    long finding;
    if (sources.isEmpty()) {
      long runScope =
          jdbc.queryForObject(
              "INSERT INTO secret_run_scopes(run_id,scope_id,scope_revision,collection_status)"
                  + " SELECT ?,scope_id,revision,'SUCCEEDED' FROM secret_connection_scopes WHERE"
                  + " scope_id=? RETURNING run_scope_id",
              Long.class,
              run,
              location.get("scope_id"));
      long tool =
          jdbc.queryForObject(
              "INSERT INTO secret_tool_runs(run_scope_id,engine,engine_version,config_hash,status)"
                  + " VALUES(?,'GITLEAKS','query-fixture','query-fixture','SUCCEEDED') RETURNING"
                  + " tool_run_id",
              Long.class,
              runScope);
      finding =
          jdbc.queryForObject(
              "INSERT INTO"
                  + " secret_findings(occurrence_id,run_id,tool_run_id,finding_key,rule_id,rule_version,detected_at)"
                  + " VALUES(?,?,?,gen_random_uuid()::text,'query-fixture','1',?) RETURNING"
                  + " finding_id",
              Long.class,
              occurrence,
              run,
              tool,
              requested);
    } else finding = ((Number) sources.getFirst().get("finding_id")).longValue();
    return jdbc.queryForObject(
        """
INSERT INTO secret_validation_attempts(credential_set_id,job_id,run_id,validator_id,validator_version,endpoint_class,
  requested_at,completed_at,provider_checked_at,result,reason_code,evidence_version,attempt_state,request_sent_at,
  scope_id,occurrence_id,source_finding_id,source_object_version_digest,credential_revision,scope_revision,
  validation_revision,validation_approval_revision,validation_profile_version,action_context_digest,dedup_key,
  cycle_key,attempt_no,reservation_generation,reservation_token,current_eligible,ineligible_reason_code)
SELECT v.credential_set_id,?,?,'AWS_STS_GET_CALLER_IDENTITY','1','AWS_STS',?,?,?,?,?,1,'COMPLETED',?,
  v.scope_id,v.occurrence_id,?,sha256(convert_to(jsonb_build_array(o.source_object_ref,o.latest_object_version,o.location_key)::text,'UTF8')),
  v.credential_revision,v.scope_revision,v.validation_revision,v.validation_approval_revision,v.connection_profile,
  decode(v.context_version,'hex'),sha256(convert_to(gen_random_uuid()::text,'UTF8')),gen_random_uuid()::text,1,1,
  gen_random_uuid(),true,NULL
FROM secret_validation_context v JOIN secret_occurrences o USING(occurrence_id) WHERE v.occurrence_id=?
RETURNING attempt_id
""",
        Long.class,
        job,
        run,
        requested,
        completed,
        checked,
        result,
        reason,
        "UNCHECKED".equals(result) ? null : requested,
        finding,
        occurrence);
  }
}
