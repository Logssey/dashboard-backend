package com.logssey.secret.risk;

import static org.assertj.core.api.Assertions.*;

import com.logssey.secret.risk.core.SecretSeverityEngine;
import java.util.*;
import org.junit.jupiter.api.Test;

class SecretSeverityEngineTest {
  static List<SecretSeverityEngine.Rule> rules() {
    return List.of(
        rule("R00", 0, "NORMAL", null, null, null, null, "NOT_APPLICABLE", null),
        rule("R01", 1, "ABNORMAL", null, null, null, "CONFIRMED", "ASSESSED", "CRITICAL"),
        rule(
            "R02",
            2,
            "ABNORMAL",
            List.of("BROAD"),
            "CONFIRMED",
            "ADMIN",
            null,
            "ASSESSED",
            "CRITICAL"),
        rule(
            "R03",
            3,
            "ABNORMAL",
            List.of("BOUNDED"),
            "CONFIRMED",
            "ADMIN",
            null,
            "ASSESSED",
            "HIGH"),
        rule(
            "R04",
            4,
            "ABNORMAL",
            List.of("BROAD", "BOUNDED"),
            "CONFIRMED",
            "IMPORTANT",
            null,
            "ASSESSED",
            "HIGH"),
        rule(
            "R05",
            5,
            "ABNORMAL",
            List.of("BROAD", "BOUNDED"),
            "CONFIRMED",
            "LIMITED",
            null,
            "ASSESSED",
            "MEDIUM"),
        rule(
            "R06",
            6,
            "ABNORMAL",
            List.of("BROAD"),
            "CONFIRMED",
            "MINIMAL",
            null,
            "ASSESSED",
            "MEDIUM"),
        rule(
            "R07",
            7,
            "ABNORMAL",
            List.of("BOUNDED"),
            "CONFIRMED",
            "MINIMAL",
            null,
            "ASSESSED",
            "LOW"),
        rule("R99", 99, null, null, null, null, null, "UNASSESSED", null));
  }

  static SecretSeverityEngine.Rule rule(
      String id,
      int n,
      String exposure,
      List<String> ranges,
      String credential,
      String impact,
      String abuse,
      String status,
      String severity) {
    var c = new HashMap<String, Object>();
    for (String axis : SecretSeverityEngine.AXES.keySet()) c.put(axis, Map.of("op", "ANY"));
    for (var p :
        List.of(
            new Object[] {"exposure", exposure},
            new Object[] {"credential", credential},
            new Object[] {"impact", impact},
            new Object[] {"abuse", abuse}))
      if (p[1] != null) c.put((String) p[0], Map.of("op", "EQ", "value", p[1]));
    if (ranges != null) c.put("exposureRange", Map.of("op", "IN", "values", ranges));
    return new SecretSeverityEngine.Rule(id, n, c, status, severity);
  }

  static Map<String, String> input(
      String exposure,
      String range,
      String credential,
      String impact,
      String abuse,
      String validity) {
    return Map.of(
        "exposure",
        exposure,
        "exposureRange",
        range,
        "credential",
        credential,
        "impact",
        impact,
        "abuse",
        abuse,
        "validity",
        validity);
  }

  @Test
  void everyGoldenRuleAndValidityIndependence() {
    var engine = new SecretSeverityEngine();
    for (String validity : List.of("VALID", "INVALID", "UNKNOWN", "UNCHECKED")) {
      assertRule(engine, "R02", "BROAD", "ADMIN", validity);
      assertRule(engine, "R03", "BOUNDED", "ADMIN", validity);
      assertRule(engine, "R04", "BROAD", "IMPORTANT", validity);
      assertRule(engine, "R04", "BOUNDED", "IMPORTANT", validity);
      assertRule(engine, "R05", "BROAD", "LIMITED", validity);
      assertRule(engine, "R06", "BROAD", "MINIMAL", validity);
      assertRule(engine, "R07", "BOUNDED", "MINIMAL", validity);
    }
  }

  void assertRule(
      SecretSeverityEngine e, String rule, String range, String impact, String validity) {
    assertThat(
            e.evaluate(
                    input("ABNORMAL", range, "CONFIRMED", impact, "NOT_CONFIRMED", validity),
                    rules())
                .ruleId())
        .isEqualTo(rule);
  }

  @Test
  void normalAndIncidentHavePathSpecificRequirements() {
    var e = new SecretSeverityEngine();
    assertThat(
            e.evaluate(
                    input(
                        "NORMAL", "UNKNOWN", "CANDIDATE", "UNKNOWN", "NOT_CONFIRMED", "UNCHECKED"),
                    rules())
                .ruleId())
        .isEqualTo("R00");
    assertThat(
            e.evaluate(
                    input("ABNORMAL", "UNKNOWN", "CANDIDATE", "UNKNOWN", "CONFIRMED", "INVALID"),
                    rules())
                .ruleId())
        .isEqualTo("R01");
    var conflict =
        e.evaluate(
            input("NORMAL", "UNKNOWN", "CANDIDATE", "UNKNOWN", "CONFIRMED", "UNCHECKED"), rules());
    assertThat(conflict.ruleId()).isEqualTo("R99");
    assertThat(conflict.reasons()).contains("EXPOSURE_INCIDENT_CONFLICT");
  }

  @Test
  void unknownNeverActsAsWildcardAndCodeConditionsAreRejected() {
    var e = new SecretSeverityEngine();
    assertThat(
            e.evaluate(
                    input("ABNORMAL", "UNKNOWN", "CONFIRMED", "ADMIN", "NOT_CONFIRMED", "VALID"),
                    rules())
                .status())
        .isEqualTo("UNASSESSED");
    var bad = new ArrayList<>(rules());
    var c = new HashMap<>(bad.getFirst().conditions());
    c.put("exposure", Map.of("op", "SQL", "value", "fixture-not-executed"));
    bad.set(0, new SecretSeverityEngine.Rule("R00", 0, c, "NOT_APPLICABLE", null));
    assertThatThrownBy(
            () ->
                e.evaluate(
                    input(
                        "NORMAL", "UNKNOWN", "CANDIDATE", "UNKNOWN", "NOT_CONFIRMED", "UNCHECKED"),
                    bad))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
