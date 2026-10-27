package com.logssey.runtime.query.dto;

import java.util.List;

public record RuntimeOverviewResponse(
        Period period,
        Summary summary,
        List<RuleCount> findingsByRule,
        SensorSummary sensorSummary,
        String collectionState,
        String generatedAt) {

    public record Period(String from, String to) {
    }

    public record Summary(long runtimeEventCount, long suppressedEventCount, long rateLimitedEventCount,
                          long unreviewedFindingCount, long affectedWorkloadCount,
                          long unresolvedAssetEventCount) {
    }

    public record RuleCount(String ruleKey, String title, long count) {
    }

    public record SensorSummary(long healthy, long degraded, long offline, long unknown) {
    }
}
