package com.logssey.secret.risk.permission;

import com.logssey.secret.access.*;
import com.logssey.secret.permission.core.SecretPermissionContext;
import java.time.OffsetDateTime;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import tools.jackson.databind.json.JsonMapper;

/** Candidate-derived signals obey the same collector ACL and approval baseline as confirmation. */
public final class SecretPermissionObservationEligibility {
  private SecretPermissionObservationEligibility() {}

  public static boolean current(JdbcTemplate jdbc, SecretAccessService access, SecretPrincipal actor,
      Map<String, Object> source, Map<String, Object> observation, OffsetDateTime now) {
    if (!(observation.get("collector_connection_id") instanceof Number collector)
        || !access.canReadConnectionFacts(actor, collector.longValue())
        || !"ACTIVE".equals(source.get("connection_status")) || !Boolean.TRUE.equals(source.get("scope_enabled"))
        || source.get("identity_id") == null || !Objects.equals(source.get("identity_id"), observation.get("identity_id"))
        || "UNSUPPORTED".equals(observation.get("status"))) return false;
    var expiry = SecretPermissionContext.time(observation.get("expires_at"));
    var observed = SecretPermissionContext.time(observation.get("observed_at"));
    if (expiry == null || !expiry.isAfter(now) || observed == null || observed.isAfter(now.plusMinutes(5))
        || !observed.plusHours(24).isAfter(now)) return false;
    Map<?, ?> baseline = new JsonMapper().readValue(observation.get("baseline").toString(), Map.class);
    if (!Objects.equals(baseline.get("sourceContextVersion"), SecretPermissionContext.sourceVersion(source))
        || !(baseline.get("collectorScopeId") instanceof Number scope)) return false;
    var rows = jdbc.queryForList("SELECT c.provider,c.auth_ref,c.scope_version,c.status,s.scope_id,s.revision,s.approved_ref,s.enabled,s.content_type,s.history_limit"
        + " FROM secret_connections c JOIN secret_connection_scopes s USING(connection_id) WHERE c.connection_id=? AND s.scope_id=?",
        collector.longValue(), scope.longValue());
    if (rows.isEmpty()) return false;
    var row = rows.getFirst();
    if (!"ACTIVE".equals(row.get("status")) || !Boolean.TRUE.equals(row.get("enabled"))) return false;
    for (var pair : List.of(Map.entry("auth_ref", "collectorAuthRef"), Map.entry("scope_version", "collectorScopeVersion"),
        Map.entry("scope_id", "collectorScopeId"), Map.entry("revision", "collectorScopeRevision"),
        Map.entry("approved_ref", "collectorApprovedRef")))
      if (!Objects.toString(row.get(pair.getKey()), "").equals(Objects.toString(baseline.get(pair.getValue()), ""))) return false;
    if ("AWS".equals(source.get("issuer")))
      return "AWS".equals(row.get("provider")) && "IAM_ACCESS_KEY_METADATA".equals(row.get("content_type"))
          && Objects.equals(row.get("approved_ref"), "aws://" + source.get("account_ref") + "/global/iam/access-keys")
          && (row.get("history_limit") == null || "CURRENT_STATE_ONLY".equals(row.get("history_limit")));
    return "GITHUB".equals(source.get("issuer")) && "GITHUB".equals(source.get("source_provider"))
        && "GITHUB".equals(row.get("provider")) && Objects.equals(source.get("connection_id"), collector.longValue())
        && Objects.equals(source.get("scope_id"), scope.longValue());
  }
}
