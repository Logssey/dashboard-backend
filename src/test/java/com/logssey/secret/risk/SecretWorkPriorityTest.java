package com.logssey.secret.risk;

import static org.assertj.core.api.Assertions.*;
import java.time.OffsetDateTime;
import org.junit.jupiter.api.Test;

class SecretWorkPriorityTest {
  @Test void nightsAndWeekendsDoNotPretendToHaveContinuousCoverage() {
    var friday = OffsetDateTime.parse("2026-11-06T17:30:00+09:00");
    assertThat(SecretWorkPriority.plusBusinessHours(friday, 1))
        .isEqualTo(OffsetDateTime.parse("2026-11-09T09:30:00+09:00"));
    assertThat(SecretWorkPriority.plusBusinessHours(friday, 4))
        .isEqualTo(OffsetDateTime.parse("2026-11-09T12:30:00+09:00"));
    assertThat(SecretWorkPriority.plusBusinessHours(OffsetDateTime.parse("2026-11-07T12:00:00+09:00"), 9))
        .isEqualTo(OffsetDateTime.parse("2026-11-09T18:00:00+09:00"));
  }
  @Test void priorityDoesNotInventSeverityAndValidityDoesNotLowerHeldCritical() {
    var now = OffsetDateTime.parse("2026-11-07T12:00:00+09:00");
    var held = SecretWorkPriority.describe("CRITICAL", true, false, true, false, false, false, now, now);
    assertThat(held).containsEntry("level", "IMMEDIATE").containsEntry("operatingHoursNow", false);
    var candidate = SecretWorkPriority.describe(null, true, false, true, true, false, true, null, now);
    assertThat(candidate).containsEntry("level", "PRIORITY").containsEntry("acknowledgeDueAt", null);
    assertThat(SecretWorkPriority.describe(null, true, false, true, false, true, true, now, now))
        .containsEntry("level", "GENERAL");
    assertThat(SecretWorkPriority.describe(null, false, true, true, false, false, false, now, now))
        .containsEntry("level", "INVENTORY");
  }
  @Test void readingLaterDoesNotMoveFixedTargets() {
    var start = OffsetDateTime.parse("2026-11-06T10:00:00+09:00");
    var first = SecretWorkPriority.describe("HIGH", false, false, true, false, false, false, start, start);
    var later = SecretWorkPriority.describe("HIGH", false, false, true, false, false, false, start, start.plusDays(4));
    assertThat(later.get("acknowledgeDueAt")).isEqualTo(first.get("acknowledgeDueAt"));
    assertThat(later.get("planDueAt")).isEqualTo(first.get("planDueAt"));
  }
}
