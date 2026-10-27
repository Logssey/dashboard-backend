package com.logssey.runtime.query;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.runtime.query.RuntimeQueryRepository.CurrentFinding;
import com.logssey.runtime.query.RuntimeQueryRepository.RuntimeCounts;
import com.logssey.runtime.query.dto.RuntimeFindingListResponse;
import com.logssey.runtime.query.dto.RuntimeFindingResponse;
import com.logssey.runtime.query.dto.RuntimeFindingUpdateRequest;
import com.logssey.runtime.query.dto.RuntimeOverviewResponse;
import com.logssey.runtime.query.dto.RuntimeOverviewResponse.Period;
import com.logssey.runtime.query.dto.RuntimeOverviewResponse.SensorSummary;
import com.logssey.runtime.query.dto.RuntimeOverviewResponse.Summary;
import com.logssey.runtime.query.dto.RuntimeSensorListResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class RuntimeQueryService {

    private static final Set<String> REVIEW_STATUSES = Set.of("UNREVIEWED", "REVIEWED");
    private static final Set<String> ACTION_STATUSES = Set.of("OPEN", "IN_PROGRESS", "RESOLVED", "RISK_ACCEPTED");
    private static final Set<String> DISPOSITIONS = Set.of("UNDECIDED", "EXPECTED", "ACTION_REQUIRED");

    private final RuntimeQueryRepository repository;
    private final RuntimeSensorHealthEvaluator sensorHealthEvaluator;
    private final int expectedWorkerCount;

    public RuntimeQueryService(RuntimeQueryRepository repository,
                               RuntimeSensorHealthEvaluator sensorHealthEvaluator,
                               @Value("${logssey.runtime.expected-worker-count:3}") int expectedWorkerCount) {
        this.repository = repository;
        this.sensorHealthEvaluator = sensorHealthEvaluator;
        this.expectedWorkerCount = Math.max(0, expectedWorkerCount);
    }

    public RuntimeOverviewResponse overview(String clusterId, Instant from, Instant to) {
        validateRange(from, to);
        RuntimeCounts counts = repository.counts(clusterId, from, to);
        List<RuntimeSensorListResponse.SensorItem> sensors = effectiveSensors(clusterId);
        long expectedSlots = (long) expectedWorkerCount * 2;
        long healthy = countStatus(sensors, "HEALTHY");
        long degraded = countStatus(sensors, "DEGRADED");
        long offline = countStatus(sensors, "OFFLINE");
        long unknown = countStatus(sensors, "UNKNOWN");
        long missing = Math.max(0, expectedSlots - sensors.size());
        String collectionState = sensors.isEmpty() ? "NOT_INSTALLED"
                : offline > 0 ? "OFFLINE"
                : degraded > 0 || unknown > 0 || missing > 0 ? "DEGRADED"
                : "HEALTHY";
        return new RuntimeOverviewResponse(
                new Period(from.toString(), to.toString()),
                new Summary(counts.eventCount(), counts.suppressedCount(), counts.rateLimitedCount(),
                        counts.unreviewedCount(), counts.workloadCount(), counts.unresolvedCount()),
                repository.countsByRule(clusterId, from, to),
                new SensorSummary(healthy, degraded, offline, unknown + missing),
                collectionState,
                Instant.now().toString());
    }

    public RuntimeFindingListResponse findings(String clusterId, String namespace,
                                               String reviewStatus, String ruleKey, int limit) {
        if (limit < 1 || limit > 200) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "limit은 1~200 사이여야 합니다.");
        }
        if (!"ALL".equals(reviewStatus) && !REVIEW_STATUSES.contains(reviewStatus)) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "reviewStatus는 ALL, UNREVIEWED, REVIEWED 중 하나여야 합니다.");
        }
        List<RuntimeFindingResponse> items = repository.findFindings(clusterId, namespace, reviewStatus, ruleKey, limit);
        return new RuntimeFindingListResponse(
                items, repository.countFindings(clusterId, namespace, reviewStatus, ruleKey));
    }

    public RuntimeFindingResponse finding(long findingId) {
        return repository.findFinding(findingId)
                .orElseThrow(() -> new ApiException(ErrorCode.RUNTIME_FINDING_NOT_FOUND));
    }

    public RuntimeSensorListResponse sensors(String clusterId) {
        List<RuntimeSensorListResponse.SensorItem> items = effectiveSensors(clusterId);
        long expectedSlots = (long) expectedWorkerCount * 2;
        boolean sensorMissing = items.size() < expectedSlots;
        String collectionState = items.isEmpty() ? "NOT_INSTALLED"
                : items.stream().anyMatch(item -> "OFFLINE".equals(item.status())) ? "OFFLINE"
                : sensorMissing || items.stream().anyMatch(item -> !"HEALTHY".equals(item.status())) ? "DEGRADED"
                : "HEALTHY";
        return new RuntimeSensorListResponse(items, collectionState);
    }

    private List<RuntimeSensorListResponse.SensorItem> effectiveSensors(String clusterId) {
        return sensorHealthEvaluator.evaluate(repository.findSensors(clusterId), Instant.now());
    }

    private static long countStatus(List<RuntimeSensorListResponse.SensorItem> sensors, String status) {
        return sensors.stream().filter(sensor -> status.equals(sensor.status())).count();
    }

    @Transactional
    public RuntimeFindingResponse updateFinding(long findingId, String loginId, RuntimeFindingUpdateRequest request) {
        CurrentFinding current = repository.findCurrent(findingId)
                .orElseThrow(() -> new ApiException(ErrorCode.RUNTIME_FINDING_NOT_FOUND));
        if (current.version() != request.version()) {
            throw new ApiException(ErrorCode.FINDING_VERSION_CONFLICT);
        }

        String review = valueOrCurrent(request.reviewStatus(), current.reviewStatus(), REVIEW_STATUSES, "reviewStatus");
        String action = valueOrCurrent(request.actionStatus(), current.actionStatus(), ACTION_STATUSES, "actionStatus");
        String disposition = valueOrCurrent(request.disposition(), current.disposition(), DISPOSITIONS, "disposition");
        if (!repository.assigneeExists(request.assigneeUserId())) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "담당자 사용자를 찾을 수 없습니다.");
        }
        String note = request.note() == null ? current.note() : request.note().trim();
        long changedBy = repository.findUserId(loginId);
        int updated = repository.updateFinding(findingId, changedBy, current, request, review, action,
                disposition, request.assigneeUserId(), note);
        if (updated == 0) {
            throw new ApiException(ErrorCode.FINDING_VERSION_CONFLICT);
        }
        return finding(findingId);
    }

    private static String valueOrCurrent(String requested, String current, Set<String> allowed, String field) {
        if (requested == null) {
            return current;
        }
        if (!allowed.contains(requested)) {
            throw new ApiException(ErrorCode.INVALID_INPUT, field + " 값이 올바르지 않습니다.");
        }
        return requested;
    }

    private static void validateRange(Instant from, Instant to) {
        if (!from.isBefore(to) || Duration.between(from, to).compareTo(Duration.ofDays(31)) > 0) {
            throw new ApiException(ErrorCode.INVALID_INPUT, "조회 기간은 31일 이내여야 합니다.");
        }
    }
}
