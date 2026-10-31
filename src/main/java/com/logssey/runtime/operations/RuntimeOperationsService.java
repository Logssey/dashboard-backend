package com.logssey.runtime.operations;

import java.time.Duration;
import java.time.Instant;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.runtime.operations.RuntimeOperationsRepository.MaintenanceRun;
import com.logssey.runtime.operations.RuntimeOperationsRepository.OperationalCounts;
import com.logssey.runtime.operations.dto.RuntimeMaintenanceResponse;
import com.logssey.runtime.operations.dto.RuntimeOperationsHealthResponse;
import com.logssey.runtime.operations.dto.RuntimeOperationsHealthResponse.EventWindow;
import com.logssey.runtime.operations.dto.RuntimeOperationsHealthResponse.LastMaintenance;
import com.logssey.runtime.operations.dto.RuntimeOperationsHealthResponse.Retention;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class RuntimeOperationsService {

    private static final int HEALTH_WINDOW_MINUTES = 15;

    private final RuntimeOperationsRepository repository;
    private final Duration rateWindowRetention;
    private final int maintenanceBatchSize;

    public RuntimeOperationsService(
            RuntimeOperationsRepository repository,
            @Value("${logssey.runtime.rate-window-retention:P7D}") Duration rateWindowRetention,
            @Value("${logssey.runtime.maintenance-batch-size:1000}") int maintenanceBatchSize) {
        this.repository = repository;
        this.rateWindowRetention = rateWindowRetention.isNegative() || rateWindowRetention.isZero()
                ? Duration.ofDays(7) : rateWindowRetention;
        this.maintenanceBatchSize = Math.max(1, Math.min(10_000, maintenanceBatchSize));
    }

    public RuntimeOperationsHealthResponse health(String loginId) {
        requireAdmin(loginId);
        Instant now = Instant.now();
        OperationalCounts counts = repository.countsSince(now.minus(Duration.ofMinutes(HEALTH_WINDOW_MINUTES)));
        long backlog = repository.payloadBacklog();
        Instant oldestDue = repository.oldestDuePayload();
        MaintenanceRun last = repository.lastMaintenance().orElse(null);
        String status = counts.failed() > 0 ? "DEGRADED"
                : counts.rateLimited() > 0 || backlog > 0 ? "ATTENTION"
                : "HEALTHY";
        LastMaintenance lastResponse = last == null ? null : new LastMaintenance(
                last.completedAt().toString(), last.payloadsPurged(), last.rateWindowsDeleted(),
                last.remainingPayloadBacklog());
        return new RuntimeOperationsHealthResponse(
                status,
                new EventWindow(HEALTH_WINDOW_MINUTES, counts.received(), counts.grouped(), counts.suppressed(),
                        counts.rateLimited(), counts.ignored(), counts.failed()),
                new Retention(backlog, oldestDue == null ? null : oldestDue.toString()),
                lastResponse,
                now.toString());
    }

    @Transactional
    public RuntimeMaintenanceResponse runManual(String loginId) {
        long actorUserId = requireAdmin(loginId);
        return execute("USER", actorUserId);
    }

    @Transactional
    public RuntimeMaintenanceResponse runScheduled() {
        return execute("SCHEDULE", null);
    }

    private RuntimeMaintenanceResponse execute(String triggeredBy, Long actorUserId) {
        if (!repository.acquireMaintenanceLock()) {
            return new RuntimeMaintenanceResponse(false, 0, 0, repository.payloadBacklog(), Instant.now().toString());
        }
        Instant startedAt = Instant.now();
        long purged = repository.purgeDuePayloads(maintenanceBatchSize);
        long deletedWindows = repository.deleteRateWindowsBefore(startedAt.minus(rateWindowRetention));
        long backlog = repository.payloadBacklog();
        Instant completedAt = Instant.now();
        repository.recordMaintenance(triggeredBy, actorUserId, purged, deletedWindows, backlog,
                startedAt, completedAt);
        return new RuntimeMaintenanceResponse(true, purged, deletedWindows, backlog, completedAt.toString());
    }

    private long requireAdmin(String loginId) {
        if (loginId == null || loginId.isBlank()) {
            throw new ApiException(ErrorCode.UNAUTHENTICATED);
        }
        return repository.adminUserId(loginId)
                .orElseThrow(() -> new ApiException(ErrorCode.FORBIDDEN));
    }
}
