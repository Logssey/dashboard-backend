package com.logssey.help;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Per-user and global call limits for the help chatbot, counted in server memory (team decision: no DB table).
 * Counts reset when the process restarts; the Anthropic workspace spend limit is the hard backstop.
 * A call is charged before dispatch and never refunded, because the provider may already have billed it.
 */
@Component
class HelpCallBudget {

    private static final Duration MINUTE = Duration.ofMinutes(1);
    private final Limits limits;
    private final Clock clock;
    private final ZoneId zone;

    private final Map<String, Deque<Instant>> userMinute = new HashMap<>();
    private final Map<String, Integer> userDay = new HashMap<>();
    private final Deque<Instant> globalMinute = new ArrayDeque<>();
    private final Set<String> busy = new HashSet<>();
    private int globalDay;
    private LocalDate day;

    @Autowired
    HelpCallBudget(@Value("${logssey.help.limit.user-per-minute:5}") int userPerMinute,
                   @Value("${logssey.help.limit.user-per-day:15}") int userPerDay,
                   @Value("${logssey.help.limit.global-per-minute:20}") int globalPerMinute,
                   @Value("${logssey.help.limit.global-per-day:40}") int globalPerDay) {
        this(new Limits(userPerMinute, userPerDay, globalPerMinute, globalPerDay),
                Clock.system(ZoneId.of("Asia/Seoul")));
    }

    HelpCallBudget(Limits limits, Clock clock) {
        this.limits = Objects.requireNonNull(limits);
        this.clock = Objects.requireNonNull(clock);
        this.zone = clock.getZone();
        this.day = LocalDate.now(clock);
    }

    /** How many calls this user has left today, without using one (for answers served from the cache). */
    synchronized int remainingToday(String principal) {
        if (principal == null || principal.isBlank()) return 0;
        rollDay(clock.instant());
        return Math.max(0, limits.userPerDay() - userDay.getOrDefault(principal, 0));
    }

    synchronized Permit acquire(String principal) {
        if (principal == null || principal.isBlank() || principal.length() > 100) {
            return Permit.denied("CONFIGURATION_INVALID", 0, 0);
        }
        Instant now = clock.instant();
        rollDay(now);
        Deque<Instant> mine = userMinute.computeIfAbsent(principal, key -> new ArrayDeque<>());
        prune(mine, now);
        prune(globalMinute, now);
        int usedToday = userDay.getOrDefault(principal, 0);
        int remainingDay = Math.max(0, limits.userPerDay() - usedToday);

        if (busy.contains(principal)) return Permit.denied("BUSY", 5, remainingDay);
        if (usedToday >= limits.userPerDay() || globalDay >= limits.globalPerDay()) {
            return Permit.denied("DAILY_LIMIT", 0, remainingDay);
        }
        if (mine.size() >= limits.userPerMinute()) {
            long wait = Duration.between(now, mine.peekFirst().plus(MINUTE)).toSeconds() + 1;
            return Permit.denied("RATE_LIMITED", (int) Math.max(1, Math.min(wait, 60)), remainingDay);
        }
        if (globalMinute.size() >= limits.globalPerMinute()) {
            long wait = Duration.between(now, globalMinute.peekFirst().plus(MINUTE)).toSeconds() + 1;
            return Permit.denied("RATE_LIMITED", (int) Math.max(1, Math.min(wait, 60)), remainingDay);
        }

        mine.addLast(now);
        globalMinute.addLast(now);
        userDay.put(principal, usedToday + 1);
        globalDay++;
        busy.add(principal);
        return new Permit(true, "READY", 0, remainingDay - 1, principal, this);
    }

    private synchronized void release(String principal) {
        busy.remove(principal);
    }

    private void rollDay(Instant now) {
        LocalDate today = LocalDate.ofInstant(now, zone);
        if (!today.equals(day)) {
            day = today;
            userDay.clear();
            globalDay = 0;
        }
        userMinute.entrySet().removeIf(entry -> {
            prune(entry.getValue(), now);
            return entry.getValue().isEmpty() && !busy.contains(entry.getKey());
        });
    }

    private static void prune(Deque<Instant> calls, Instant now) {
        Instant cutoff = now.minus(MINUTE);
        while (!calls.isEmpty() && !calls.peekFirst().isAfter(cutoff)) calls.removeFirst();
    }

    record Limits(int userPerMinute, int userPerDay, int globalPerMinute, int globalPerDay) {
        Limits {
            if (userPerMinute < 1 || userPerDay < 1 || globalPerMinute < 1 || globalPerDay < 1) {
                throw new IllegalArgumentException("Help call limits must be positive");
            }
        }
    }

    static final class Permit {
        private final boolean allowed;
        private final String reasonCode;
        private final int retryAfterSeconds;
        private final int remainingToday;
        private final String principal;
        private final HelpCallBudget owner;
        private final AtomicBoolean closed = new AtomicBoolean();

        private Permit(boolean allowed, String reasonCode, int retryAfterSeconds, int remainingToday,
                       String principal, HelpCallBudget owner) {
            this.allowed = allowed;
            this.reasonCode = reasonCode;
            this.retryAfterSeconds = retryAfterSeconds;
            this.remainingToday = remainingToday;
            this.principal = principal;
            this.owner = owner;
        }

        static Permit denied(String reasonCode, int retryAfterSeconds, int remainingToday) {
            return new Permit(false, reasonCode, retryAfterSeconds, remainingToday, null, null);
        }

        boolean allowed() { return allowed; }
        String reasonCode() { return reasonCode; }
        int retryAfterSeconds() { return retryAfterSeconds; }
        int remainingToday() { return remainingToday; }

        /** Ends the in-flight slot. The call stays counted against the minute and day limits. */
        void complete() {
            if (allowed && owner != null && closed.compareAndSet(false, true)) owner.release(principal);
        }
    }
}
