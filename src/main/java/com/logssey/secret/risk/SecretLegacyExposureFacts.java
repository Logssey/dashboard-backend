package com.logssey.secret.risk;

import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/** Explains existing decisions after the caller has applied the live occurrence ACL. */
final class SecretLegacyExposureFacts {
  private final JdbcTemplate jdbc;

  SecretLegacyExposureFacts(JdbcTemplate jdbc) {
    this.jdbc = jdbc;
  }

  Map<Long, Map<String, Object>> read(Collection<Long> authorizedOccurrences) {
    if (authorizedOccurrences.isEmpty()) return Map.of();
    var result = new LinkedHashMap<Long, Map<String, Object>>();
    for (var row :
        new NamedParameterJdbcTemplate(jdbc)
            .queryForList(
                """
                SELECT o.occurrence_id,o.exposure_status,o.policy_recheck_required,s.revision,
                  e.assessment_id,e.decision,e.scope_revision,e.assessed_at,e.decision_source
                FROM secret_occurrences o JOIN secret_connection_scopes s USING(scope_id)
                JOIN LATERAL(SELECT * FROM secret_exposure_assessments e
                  WHERE e.occurrence_id=o.occurrence_id ORDER BY version DESC LIMIT 1)e ON true
                WHERE o.occurrence_id IN(:ids) AND e.decision IN('NORMAL','ABNORMAL')
                """,
                Map.of("ids", authorizedOccurrences))) {
      var reasons = new ArrayList<String>();
      if (row.get("scope_revision") == null) reasons.add("LEGACY_EXPOSURE_SCOPE_UNVERSIONED");
      else if (!Objects.equals(row.get("scope_revision"), row.get("revision")))
        reasons.add("EXPOSURE_SCOPE_REVISION_CHANGED");
      if (Boolean.TRUE.equals(row.get("policy_recheck_required")))
        reasons.add("EXPOSURE_RECONFIRMATION_REQUIRED");
      var item = new LinkedHashMap<String, Object>();
      item.put("assessmentId", row.get("assessment_id"));
      item.put("decision", row.get("decision"));
      item.put("scopeRevision", row.get("scope_revision"));
      item.put("currentScopeRevision", row.get("revision"));
      item.put(
          "assessedAt",
          com.logssey.secret.risk.core.SecretRiskAssessmentStore.time(row.get("assessed_at")));
      item.put("decisionSource", row.get("decision_source"));
      item.put("needsReconfirmation", !reasons.isEmpty());
      item.put("reasonCodes", List.copyOf(reasons));
      item.put("nextAction", reasons.isEmpty() ? "NONE" : "RECONFIRM_EXPOSURE_DECISION");
      result.put(((Number) row.get("occurrence_id")).longValue(), item);
    }
    return result;
  }
}
