package com.logssey.secret.query;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SecretCaseMetricsTest {
    private final OffsetDateTime now = OffsetDateTime.parse("2026-10-31T12:00:00Z");

    @Test void anOlderSnapshotWithoutMatrixFactsIsUnavailableRatherThanAnEmptyDistribution() {
        var legacy = SecretCaseMetrics.matrix(List.of(Map.of("severity","HIGH")),true,Map.of("origin","PRODUCTION"),"old-snapshot");
        assertThat(legacy).containsEntry("status","LEGACY_UNAVAILABLE").containsEntry("total",null)
                .containsEntry("reasonCode","LEGACY_SNAPSHOT_FACTS").containsEntry("cells",List.of());
    }

    @Test void aStaleAuthenticationResultIsHistoryNotACurrentValidMatrixCell() {
        var row = observation(1,"VALID",now.minusHours(7),now.minusHours(7));
        assertThat(SecretCaseMetrics.validation(List.of(row),now))
                .containsEntry("validationStatus","UNKNOWN")
                .containsEntry("lastValidationStatus","VALID")
                .containsEntry("validationFreshness","STALE")
                .containsEntry("validationCheckedAt",now.minusHours(7))
                .containsEntry("validationReasonCode","CHECK_PERIOD_EXCEEDED");
        var current = observation(2,"VALID",now.minusMinutes(5),now.minusMinutes(5));
        assertThat(SecretCaseMetrics.validation(List.of(current),now))
                .containsEntry("validationStatus","VALID")
                .containsEntry("validationFreshness","CURRENT")
                .containsEntry("validationDueAt",now.minusMinutes(5).plusHours(6));
        assertThat(SecretCaseMetrics.validation(List.of(observation(3,"INVALID",now.minusHours(6),now.minusHours(6))),now))
                .containsEntry("validationStatus","UNKNOWN").containsEntry("validationFreshness","STALE");
    }

    @Test void aNewerUnsuccessfulAttemptCannotBeHiddenBehindAnOlderSuccess() {
        var success = observation(1,"VALID",now.minusMinutes(10),now.minusMinutes(10));
        var unavailable = observation(2,"UNKNOWN",now.minusMinutes(1),null);
        when(unavailable.validationReason()).thenReturn("PROVIDER_UNAVAILABLE");
        assertThat(SecretCaseMetrics.validation(List.of(success,unavailable),now))
                .containsEntry("validationStatus","UNKNOWN")
                .containsEntry("validationFreshness","UNAVAILABLE")
                .containsEntry("validationReasonCode","PROVIDER_UNAVAILABLE");
    }

    @Test void anUnverifiedMaterialActionCannotReuseAnotherLocationsSuccess() {
        var pending = observation(1,"UNCHECKED",now.minusMinutes(10),null);
        when(pending.validationReason()).thenReturn("POST_ACTION_VALIDATION_REQUIRED");
        var success = observation(2,"VALID",now.minusMinutes(1),now.minusMinutes(1));
        assertThat(SecretCaseMetrics.validation(List.of(pending,success),now))
                .containsEntry("validationStatus","UNCHECKED")
                .containsEntry("validationFreshness","POST_ACTION_REQUIRED");
        when(pending.actionStatus()).thenReturn("RESOLVED");
        assertThat(SecretCaseMetrics.validation(List.of(pending,success),now))
                .containsEntry("validationStatus","VALID");
    }

    @Test void noObservationAndMissingProviderTimestampDoNotBecomeAuthenticationProof() {
        assertThat(SecretCaseMetrics.validation(List.of(),now))
                .containsEntry("validationStatus","UNCHECKED")
                .containsEntry("validationReasonCode","NO_VERIFICATION_ATTEMPT");
        assertThat(SecretCaseMetrics.validation(List.of(observation(1,"VALID",now,null)),now))
                .containsEntry("validationStatus","UNKNOWN")
                .containsEntry("validationFreshness","UNAVAILABLE");
    }

    private SecretLocationRepository.Row observation(long id,String result,OffsetDateTime attempted,OffsetDateTime checked) {
        var row = mock(SecretLocationRepository.Row.class);
        when(row.occurrenceId()).thenReturn(id);
        when(row.actionStatus()).thenReturn("IN_PROGRESS");
        when(row.validity()).thenReturn(result);
        when(row.validationAttemptAt()).thenReturn(attempted);
        when(row.validationCheckedAt()).thenReturn(checked);
        return row;
    }
}
