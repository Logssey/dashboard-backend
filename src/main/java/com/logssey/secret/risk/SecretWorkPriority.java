package com.logssey.secret.risk;

import java.time.*;
import java.util.*;

/** Operational targets are independent of v2 grades and never change the assessment. */
public final class SecretWorkPriority {
  private static final ZoneId ZONE = ZoneId.of("Asia/Seoul");
  private SecretWorkPriority() {}

  public static Map<String, Object> describe(String severity, boolean unassessed,
      boolean inventory, boolean unresolved, boolean publicOriginal,
      boolean validAuthentication, boolean importantPermissionCandidate,
      OffsetDateTime basis, OffsetDateTime now) {
    String level, reason;
    if (unresolved && "CRITICAL".equals(severity)) { level = "IMMEDIATE"; reason = "UNRESOLVED_CRITICAL"; }
    else if (unresolved && "HIGH".equals(severity)) { level = "PRIORITY"; reason = "UNRESOLVED_HIGH"; }
    else if (unresolved && publicOriginal && (validAuthentication || importantPermissionCandidate)) {
      level = "PRIORITY"; reason = "PUBLIC_CREDENTIAL_REQUIRES_INVESTIGATION";
    } else if (inventory || !unresolved) { level = "INVENTORY"; reason = "NO_OPEN_EXPOSURE_ACTION"; }
    else if (!unassessed && "LOW".equals(severity)) { level = "PLANNED"; reason = "LOW_EXPOSURE"; }
    else { level = "GENERAL"; reason = unassessed ? "EVIDENCE_REQUIRES_REVIEW" : "MEDIUM_EXPOSURE"; }
    int ackHours = switch (level) { case "IMMEDIATE" -> 1; case "PRIORITY" -> 4;
      case "GENERAL" -> 9; case "PLANNED" -> 27; default -> 0; };
    int planHours = switch (level) { case "IMMEDIATE" -> 4; case "PRIORITY" -> 24; default -> 0; };
    var result = new LinkedHashMap<String, Object>();
    result.put("policyVersion", "work-priority-v1");
    result.put("level", level); result.put("reasonCodes", List.of(reason));
    result.put("clockMode", "BUSINESS_HOURS"); result.put("timeZone", ZONE.getId());
    result.put("businessHours", "MON_FRI_09_18");
    result.put("targetBasis", "FIRST_OBSERVED"); result.put("targetBasisAt", basis);
    result.put("acknowledgeDueAt", basis == null || ackHours == 0 ? null : plusBusinessHours(basis, ackHours));
    result.put("planDueAt", basis == null || planHours == 0 ? null : plusBusinessHours(basis, planHours));
    result.put("operatingHoursNow", inBusinessHours(now.atZoneSameInstant(ZONE)));
    result.put("holidayCalendarConfigured", false);
    return result;
  }

  public static OffsetDateTime plusBusinessHours(OffsetDateTime start, int hours) {
    if (hours < 0) throw new IllegalArgumentException("NEGATIVE_DURATION");
    ZonedDateTime current = nextOpening(start.atZoneSameInstant(ZONE));
    Duration remaining = Duration.ofHours(hours);
    while (!remaining.isZero()) {
      var close = current.toLocalDate().atTime(18, 0).atZone(ZONE);
      Duration available = Duration.between(current, close);
      if (remaining.compareTo(available) <= 0) return current.plus(remaining).toOffsetDateTime();
      remaining = remaining.minus(available);
      current = nextOpening(current.toLocalDate().plusDays(1).atTime(9, 0).atZone(ZONE));
    }
    return current.toOffsetDateTime();
  }

  private static boolean weekday(ZonedDateTime time) {
    return time.getDayOfWeek() != DayOfWeek.SATURDAY && time.getDayOfWeek() != DayOfWeek.SUNDAY;
  }
  private static boolean inBusinessHours(ZonedDateTime time) {
    return weekday(time) && !time.toLocalTime().isBefore(LocalTime.of(9, 0))
        && time.toLocalTime().isBefore(LocalTime.of(18, 0));
  }
  private static ZonedDateTime nextOpening(ZonedDateTime current) {
    if (weekday(current) && current.toLocalTime().isBefore(LocalTime.of(9, 0)))
      return current.toLocalDate().atTime(9, 0).atZone(ZONE);
    if (inBusinessHours(current)) return current;
    var date = current.toLocalDate();
    if (weekday(current)) date = date.plusDays(1);
    while (date.getDayOfWeek() == DayOfWeek.SATURDAY || date.getDayOfWeek() == DayOfWeek.SUNDAY)
      date = date.plusDays(1);
    return date.atTime(9, 0).atZone(ZONE);
  }
}
