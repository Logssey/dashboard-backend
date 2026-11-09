package com.logssey.secret.risk;

import static org.assertj.core.api.Assertions.*;
import com.logssey.secret.risk.core.SecretRiskApplicability;
import java.time.OffsetDateTime;
import java.util.*;
import org.junit.jupiter.api.Test;

class SecretRiskApplicabilityTest {
  private final OffsetDateTime now = OffsetDateTime.parse("2026-11-07T12:00:00Z");
  private Map<String, Object> interval() {
    return new HashMap<>(Map.of("kind", "ACCESS_SCOPE", "fact_valid_from", now.minusHours(1),
        "fact_valid_until", now.plusHours(1), "source_presence_observed_at", now.minusMinutes(30),
        "applicability_basis", "EFFECTIVE_INTERVAL"));
  }
  @Test void matchingObservationTimesDoNotFillMissingHistoricalApplicability() {
    var legacy = Map.<String, Object>of("kind", "ACCESS_SCOPE", "observed_at", now,
        "effective_from", now, "source_object_version", "same-blob");
    assertThat(SecretRiskApplicability.rejection(legacy, Map.of("latest_object_version", "same-blob"), now))
        .isEqualTo("EVIDENCE_APPLICABILITY_UNCONFIRMED");
  }
  @Test void aPublicRepositoryObservationIsNotAnAtomicPublicKeyObservation() {
    var observation = new HashMap<String, Object>(); observation.put("kind", "ACCESS_SCOPE");
    observation.put("applicability_basis", "OBSERVATION_ONLY");
    observation.put("source_object_version", "same-blob");
    assertThat(SecretRiskApplicability.rejection(observation, Map.of("latest_object_version", "same-blob"), now))
        .isEqualTo("ACCESS_COEXISTENCE_UNCONFIRMED");
  }
  @Test void sourceAndFactMustOverlapAndExpiryIsExclusive() {
    var evidence = interval();
    assertThat(SecretRiskApplicability.rejection(evidence, Map.of(), now)).isNull();
    evidence.put("source_presence_observed_at", now.minusHours(2));
    assertThat(SecretRiskApplicability.rejection(evidence, Map.of(), now)).isEqualTo("EVIDENCE_APPLICABILITY_MISMATCH");
    evidence = interval(); evidence.put("fact_valid_until", now);
    assertThat(SecretRiskApplicability.rejection(evidence, Map.of(), now)).isEqualTo("EVIDENCE_APPLICABILITY_MISMATCH");
    evidence = interval(); evidence.put("fact_valid_from", now.plusMinutes(1));
    assertThat(SecretRiskApplicability.rejection(evidence, Map.of(), now)).isEqualTo("EVIDENCE_APPLICABILITY_MISMATCH");
  }
}
