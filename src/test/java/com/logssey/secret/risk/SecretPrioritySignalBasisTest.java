package com.logssey.secret.risk;

import static org.assertj.core.api.Assertions.assertThat;
import static com.logssey.secret.risk.SecretPrioritySignalBasis.*;
import java.time.OffsetDateTime;
import java.util.List;
import org.junit.jupiter.api.Test;

class SecretPrioritySignalBasisTest {
  private final OffsetDateTime base = OffsetDateTime.parse("2026-11-06T00:00:00Z");
  private OffsetDateTime at(int hour) { return base.plusHours(hour); }
  private Observation positive(int start, int end) { return new Observation(at(start), at(end), true); }
  private Observation negative(int hour) { return new Observation(at(hour), null, false); }
  private List<Interval> intervals(OffsetDateTime now, Observation... observations) {
    return observationIntervals(List.of(observations), base, now);
  }

  @Test void repeatingPositiveObservationsDoesNotRestartTheDeadline() {
    var publicAtFirst = intervals(at(3), positive(0, 6));
    var authAtFirst = intervals(at(3), positive(1, 7));
    assertThat(currentIntersectionStart(publicAtFirst, authAtFirst, base, at(3))).isEqualTo(at(1));
    var publicLater = intervals(at(11), positive(0, 6), positive(5, 11), positive(10, 16));
    var authLater = intervals(at(11), positive(1, 7), positive(6, 12));
    assertThat(currentIntersectionStart(publicLater, authLater, base, at(11))).isEqualTo(at(1));
  }

  @Test void nonOverlappingOldObservationsCannotInventAnEarlierStart() {
    var publicSignals = intervals(at(21), positive(0, 6), positive(20, 26));
    var authSignals = intervals(at(21), positive(10, 16), positive(21, 27));
    assertThat(currentIntersectionStart(publicSignals, authSignals, base, at(21))).isEqualTo(at(21));
    assertThat(currentIntersectionStart(intervals(at(12), positive(0, 6)),
        intervals(at(12), positive(10, 16)), base, at(12))).isNull();
  }

  @Test void contraryObservationsCutTheCycleEvenBeforeTtlExpiry() {
    var publicSignals = intervals(at(5), positive(0, 6), negative(2), positive(4, 10));
    assertThat(currentIntersectionStart(publicSignals, intervals(at(5), positive(0, 8)), base, at(5)))
        .isEqualTo(at(4));
    var authSignals = intervals(at(5), positive(0, 6), negative(2), positive(3, 9));
    assertThat(currentIntersectionStart(intervals(at(5), positive(0, 8)), authSignals, base, at(5)))
        .isEqualTo(at(3));
  }

  @Test void aFreshnessGapBeginsANewCycleAndExpiryIsExclusive() {
    var publicSignals = intervals(at(10), positive(0, 6), positive(7, 13));
    assertThat(currentIntersectionStart(publicSignals, intervals(at(10), positive(1, 25)), base, at(10)))
        .isEqualTo(at(7));
    assertThat(currentIntersectionStart(intervals(at(6), positive(0, 6)),
        intervals(at(6), positive(0, 24)), base, at(6))).isNull();
  }

  @Test void overlappingAuthAndPermissionSignalsPreserveOneContinuousPriorityCycle() {
    var publicSignals = intervals(at(12), positive(0, 6), positive(5, 11), positive(10, 16));
    var credentials = List.of(new Interval(at(1), at(7)), new Interval(at(6), at(30)));
    assertThat(currentIntersectionStart(publicSignals, credentials, base, at(12))).isEqualTo(at(1));
  }

  @Test void caseOrResumptionBoundaryDoesNotUseAnEarlierCasesDeadline() {
    assertThat(currentIntersectionStart(intervals(at(5), positive(0, 6)),
        intervals(at(5), positive(1, 7)), at(4), at(5))).isEqualTo(at(4));
  }

  @Test void missingAndFutureObservationsNeverProduceAnInferredTimestamp() {
    assertThat(currentIntersectionStart(List.of(), intervals(at(3), positive(1, 7)), base, at(3))).isNull();
    assertThat(currentIntersectionStart(intervals(at(3), positive(4, 10)),
        intervals(at(3), positive(1, 7)), base, at(3))).isNull();
    assertThat(observationIntervals(List.of(new Observation(at(1), null, true)), base, at(3))).isEmpty();
  }
}
