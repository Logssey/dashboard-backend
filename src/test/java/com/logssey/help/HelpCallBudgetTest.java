package com.logssey.help;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Test;

class HelpCallBudgetTest {

    /** A clock the test can move forward. */
    static final class MutableClock extends Clock {
        private Instant now;
        private final ZoneId zone;

        MutableClock(Instant start, ZoneId zone) {
            this.now = start;
            this.zone = zone;
        }

        void advance(Duration duration) { now = now.plus(duration); }
        @Override public ZoneId getZone() { return zone; }
        @Override public Clock withZone(ZoneId other) { return new MutableClock(now, other); }
        @Override public Instant instant() { return now; }
    }

    private static MutableClock clock() {
        // 2026-11-19 10:00 KST
        return new MutableClock(Instant.parse("2026-11-19T01:00:00Z"), ZoneId.of("Asia/Seoul"));
    }

    @Test
    void limitsCallsPerUserPerMinuteAndTellsWhenToRetry() {
        var clock = clock();
        var budget = new HelpCallBudget(new HelpCallBudget.Limits(2, 40, 20, 300), clock);
        budget.acquire("admin").complete();
        clock.advance(Duration.ofSeconds(10));
        budget.acquire("admin").complete();

        var denied = budget.acquire("admin");
        assertThat(denied.allowed()).isFalse();
        assertThat(denied.reasonCode()).isEqualTo("RATE_LIMITED");
        assertThat(denied.retryAfterSeconds()).isEqualTo(51);
        assertThat(budget.acquire("viewer").allowed()).isTrue();

        clock.advance(Duration.ofSeconds(51));
        assertThat(budget.acquire("admin").allowed()).isTrue();
    }

    @Test
    void allowsOnlyOneInFlightCallPerUser() {
        var budget = new HelpCallBudget(new HelpCallBudget.Limits(5, 40, 20, 300), clock());
        var first = budget.acquire("admin");
        assertThat(budget.acquire("admin").reasonCode()).isEqualTo("BUSY");
        first.complete();
        first.complete();
        assertThat(budget.acquire("admin").allowed()).isTrue();
    }

    @Test
    void dailyLimitResetsAtKoreanMidnight() {
        var clock = clock();
        var budget = new HelpCallBudget(new HelpCallBudget.Limits(5, 2, 20, 300), clock);
        var a = budget.acquire("admin");
        assertThat(a.remainingToday()).isEqualTo(1);
        a.complete();
        clock.advance(Duration.ofMinutes(2));
        budget.acquire("admin").complete();
        clock.advance(Duration.ofMinutes(2));
        assertThat(budget.acquire("admin").reasonCode()).isEqualTo("DAILY_LIMIT");

        // 10:04 KST + 14h = 00:04 next day KST
        clock.advance(Duration.ofHours(14));
        assertThat(budget.acquire("admin").allowed()).isTrue();
    }

    @Test
    void globalLimitsApplyAcrossUsers() {
        var clock = new MutableClock(Instant.parse("2026-11-19T01:00:00Z"), ZoneOffset.ofHours(9));
        var budget = new HelpCallBudget(new HelpCallBudget.Limits(5, 40, 2, 3), clock);
        budget.acquire("a").complete();
        budget.acquire("b").complete();
        assertThat(budget.acquire("c").reasonCode()).isEqualTo("RATE_LIMITED");
        clock.advance(Duration.ofMinutes(2));
        budget.acquire("c").complete();
        assertThat(budget.acquire("d").reasonCode()).isEqualTo("DAILY_LIMIT");
    }

    @Test
    void rejectsMissingPrincipal() {
        var budget = new HelpCallBudget(new HelpCallBudget.Limits(5, 40, 20, 300), clock());
        assertThat(budget.acquire(" ").allowed()).isFalse();
    }
}
