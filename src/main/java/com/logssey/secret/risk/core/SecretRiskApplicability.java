package com.logssey.secret.risk.core;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Objects;

/** Checks fact/source co-existence independently of freshness. Missing legacy fields remain unknown. */
public final class SecretRiskApplicability {
  private SecretRiskApplicability() {}

  public static String rejection(Map<String, Object> evidence, Map<String, Object> occurrence,
      OffsetDateTime asOf) {
    if ("ABUSE_LINK".equals(evidence.get("kind"))) return null;
    var from = SecretRiskAssessmentStore.time(evidence.get("fact_valid_from"));
    var until = SecretRiskAssessmentStore.time(evidence.get("fact_valid_until"));
    var seen = SecretRiskAssessmentStore.time(evidence.get("source_presence_observed_at"));
    String basis = Objects.toString(evidence.get("applicability_basis"), "");
    if ("OBSERVATION_ONLY".equals(basis)) return "ACCESS_COEXISTENCE_UNCONFIRMED";
    if (from == null || until == null || seen == null || basis.isEmpty())
      return "EVIDENCE_APPLICABILITY_UNCONFIRMED";
    if (from.isAfter(asOf) || !until.isAfter(asOf)) return "EVIDENCE_APPLICABILITY_MISMATCH";
    if (!"EFFECTIVE_INTERVAL".equals(basis) || seen.isBefore(from) || !seen.isBefore(until)) {
      return "EVIDENCE_APPLICABILITY_MISMATCH";
    }
    return null;
  }
}
