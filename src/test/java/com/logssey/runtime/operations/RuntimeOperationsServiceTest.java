package com.logssey.runtime.operations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import com.logssey.runtime.operations.RuntimeOperationsRepository.MaintenanceRun;
import com.logssey.runtime.operations.RuntimeOperationsRepository.OperationalCounts;

import org.junit.jupiter.api.Test;

class RuntimeOperationsServiceTest {

    @Test
    void reportsDegradedWhenRecentIngestionFailed() {
        RuntimeOperationsRepository repository = mock(RuntimeOperationsRepository.class);
        RuntimeOperationsService service = service(repository);
        when(repository.adminUserId("admin")).thenReturn(Optional.of(1L));
        when(repository.countsSince(any())).thenReturn(new OperationalCounts(10, 7, 1, 1, 0, 1));
        when(repository.payloadBacklog()).thenReturn(0L);
        when(repository.lastMaintenance()).thenReturn(Optional.of(
                new MaintenanceRun(Instant.parse("2026-10-27T00:00:00Z"), 3, 2, 0)));

        var result = service.health("admin");

        assertThat(result.status()).isEqualTo("DEGRADED");
        assertThat(result.eventWindow().failed()).isEqualTo(1);
        assertThat(result.eventWindow().rateLimited()).isEqualTo(1);
    }

    @Test
    void reportsAttentionForRetentionBacklog() {
        RuntimeOperationsRepository repository = mock(RuntimeOperationsRepository.class);
        RuntimeOperationsService service = service(repository);
        when(repository.adminUserId("admin")).thenReturn(Optional.of(1L));
        when(repository.countsSince(any())).thenReturn(new OperationalCounts(4, 4, 0, 0, 0, 0));
        when(repository.payloadBacklog()).thenReturn(8L);
        when(repository.oldestDuePayload()).thenReturn(Instant.parse("2026-10-26T00:00:00Z"));
        when(repository.lastMaintenance()).thenReturn(Optional.empty());

        var result = service.health("admin");

        assertThat(result.status()).isEqualTo("ATTENTION");
        assertThat(result.retention().payloadBacklog()).isEqualTo(8);
    }

    @Test
    void scheduledMaintenanceUsesSharedLockAndRecordsOutcome() {
        RuntimeOperationsRepository repository = mock(RuntimeOperationsRepository.class);
        RuntimeOperationsService service = service(repository);
        when(repository.acquireMaintenanceLock()).thenReturn(true);
        when(repository.purgeDuePayloads(1000)).thenReturn(12L);
        when(repository.deleteRateWindowsBefore(any())).thenReturn(40L);
        when(repository.payloadBacklog()).thenReturn(2L);

        var result = service.runScheduled();

        assertThat(result.executed()).isTrue();
        assertThat(result.payloadsPurged()).isEqualTo(12);
        assertThat(result.rateWindowsDeleted()).isEqualTo(40);
        verify(repository).recordMaintenance(
                org.mockito.ArgumentMatchers.eq("SCHEDULE"),
                org.mockito.ArgumentMatchers.isNull(),
                org.mockito.ArgumentMatchers.eq(12L),
                org.mockito.ArgumentMatchers.eq(40L),
                org.mockito.ArgumentMatchers.eq(2L),
                any(), any());
    }

    @Test
    void skipsMaintenanceWhenAnotherReplicaOwnsTheLock() {
        RuntimeOperationsRepository repository = mock(RuntimeOperationsRepository.class);
        RuntimeOperationsService service = service(repository);
        when(repository.acquireMaintenanceLock()).thenReturn(false);
        when(repository.payloadBacklog()).thenReturn(5L);

        var result = service.runScheduled();

        assertThat(result.executed()).isFalse();
        assertThat(result.remainingPayloadBacklog()).isEqualTo(5);
    }

    private static RuntimeOperationsService service(RuntimeOperationsRepository repository) {
        return new RuntimeOperationsService(repository, Duration.ofDays(7), 1000);
    }
}
