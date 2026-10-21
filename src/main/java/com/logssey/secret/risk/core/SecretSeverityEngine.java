package com.logssey.secret.risk.core;

import java.util.*;

/** Pure first-match interpreter: no scripts, SQL, network, implicit defaults or clock. */
public final class SecretSeverityEngine {
  public static final Map<String, Set<String>> AXES =
      Map.of(
          "exposure",
          Set.of("NORMAL", "ABNORMAL", "UNKNOWN"),
          "exposureRange",
          Set.of("BROAD", "BOUNDED", "UNKNOWN"),
          "credential",
          Set.of("CONFIRMED", "CANDIDATE"),
          "impact",
          Set.of("ADMIN", "IMPORTANT", "LIMITED", "MINIMAL", "UNKNOWN"),
          "abuse",
          Set.of("CONFIRMED", "NOT_CONFIRMED"),
          "validity",
          Set.of("VALID", "INVALID", "UNKNOWN", "UNCHECKED"));

  public record Rule(
      String id, int ordinal, Map<String, Object> conditions, String status, String severity) {}

  public record Result(
      String ruleId,
      String status,
      String severity,
      List<String> reasons,
      Map<String, String> inputs) {}

  public Result evaluate(Map<String, String> raw, List<Rule> rules) {
    if (!raw.keySet().equals(AXES.keySet())) throw new IllegalArgumentException("INVALID_AXES");
    raw.forEach(
        (axis, value) -> {
          if (!AXES.get(axis).contains(value))
            throw new IllegalArgumentException("INVALID_AXIS_VALUE");
        });
    var input = new TreeMap<>(raw);
    var reasons = new TreeSet<String>();
    if ("NORMAL".equals(input.get("exposure")) && "CONFIRMED".equals(input.get("abuse"))) {
      input.put("exposure", "UNKNOWN");
      reasons.add("EXPOSURE_INCIDENT_CONFLICT");
    }
    var sorted =
        rules.stream()
            .sorted(Comparator.comparingInt(Rule::ordinal).thenComparing(Rule::id))
            .toList();
    if (sorted.isEmpty()
        || !"R99".equals(sorted.getLast().id())
        || sorted.stream().map(Rule::ordinal).distinct().count() != sorted.size())
      throw new IllegalArgumentException("INVALID_RULE_ORDER");
    for (Rule rule : sorted) validate(rule);
    for (Rule rule : sorted) {
      boolean match =
          rule.conditions().entrySet().stream()
              .allMatch(e -> matches(input.get(e.getKey()), cast(e.getValue())));
      if (!match) continue;
      if ("R99".equals(rule.id())) {
        if (input.get("exposure").equals("UNKNOWN")) reasons.add("EXPOSURE_UNKNOWN");
        if (input.get("exposureRange").equals("UNKNOWN")) reasons.add("EXPOSURE_RANGE_UNKNOWN");
        if (input.get("credential").equals("CANDIDATE")) reasons.add("CREDENTIAL_UNCONFIRMED");
        if (input.get("impact").equals("UNKNOWN")) reasons.add("IMPACT_UNKNOWN");
      }
      return new Result(
          rule.id(), rule.status(), rule.severity(), List.copyOf(reasons), Map.copyOf(input));
    }
    throw new IllegalArgumentException("MISSING_FALLBACK");
  }

  private void validate(Rule r) {
    if (!r.conditions().keySet().equals(AXES.keySet())
        || !Set.of("ASSESSED", "UNASSESSED", "NOT_APPLICABLE").contains(r.status())
        || ("ASSESSED".equals(r.status()) != (r.severity() != null))
        || r.severity() != null && rank(r.severity()) == 0)
      throw new IllegalArgumentException("INVALID_RULE");
    r.conditions()
        .forEach(
            (axis, value) -> {
              var c = cast(value);
              Object op = c.get("op");
              if ("ANY".equals(op)) {
                if (!c.keySet().equals(Set.of("op")))
                  throw new IllegalArgumentException("INVALID_ANY");
              } else if ("EQ".equals(op)) {
                if (!c.keySet().equals(Set.of("op", "value"))
                    || !AXES.get(axis).contains(c.get("value")))
                  throw new IllegalArgumentException("INVALID_EQ");
              } else if ("IN".equals(op)) {
                if (!c.keySet().equals(Set.of("op", "values"))
                    || !(c.get("values") instanceof List<?> list)
                    || list.isEmpty()
                    || new HashSet<>(list).size() != list.size()
                    || !AXES.get(axis).containsAll(list))
                  throw new IllegalArgumentException("INVALID_IN");
              } else throw new IllegalArgumentException("UNKNOWN_OPERATOR");
              if ("R99".equals(r.id()) && !"ANY".equals(op))
                throw new IllegalArgumentException("INVALID_FALLBACK");
            });
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> cast(Object value) {
    if (!(value instanceof Map<?, ?>)) throw new IllegalArgumentException("INVALID_CONDITION");
    return (Map<String, Object>) value;
  }

  private static boolean matches(String input, Map<String, Object> c) {
    return switch ((String) c.get("op")) {
      case "ANY" -> true;
      case "EQ" -> input.equals(c.get("value"));
      case "IN" -> ((List<?>) c.get("values")).contains(input);
      default -> false;
    };
  }

  public static int rank(String severity) {
    return severity == null
        ? 0
        : switch (severity) {
          case "LOW" -> 1;
          case "MEDIUM" -> 2;
          case "HIGH" -> 3;
          case "CRITICAL" -> 4;
          default -> 0;
        };
  }
}
