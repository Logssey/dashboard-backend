package com.logssey.runtime.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import com.logssey.common.error.ApiException;
import com.logssey.common.error.ErrorCode;
import com.logssey.runtime.policy.RuntimeSuppressionRepository.CurrentSuppression;
import com.logssey.runtime.policy.RuntimeSuppressionRepository.IdempotentSuppression;
import com.logssey.runtime.policy.dto.RuntimeSuppressionCreateRequest;
import com.logssey.runtime.policy.dto.RuntimeSuppressionResponse;
import com.logssey.runtime.policy.dto.RuntimeSuppressionRevokeRequest;

import org.junit.jupiter.api.Test;

class RuntimeSuppressionServiceTest {

    private static final Instant NOW = Instant.parse("2026-10-27T00:00:00Z");

    @Test
    void validatesSpecificTimeBoundedScope() {
        var result = RuntimeSuppressionService.validate(request(NOW.plus(Duration.ofDays(7))), NOW);

        assertThat(result.ruleKey()).isEqualTo("RUN-003");
        assertThat(result.namespace()).isEqualTo("reused");
        assertThat(result.targetNamePrefix())
                .isEqualTo("/var/run/secrets/kubernetes.io/serviceaccount/");
    }

    @Test
    void rejectsClusterWideAndLongLivedSuppressions() {
        var broad = new RuntimeSuppressionCreateRequest(
                "RUN-003", "logssey-prod", null, null, null, null, "OPEN",
                "APPROVED_OPERATION", "CHANGE:RUNTIME-100", "approved platform access",
                NOW.plus(Duration.ofDays(7)), "suppression-request-1");
        var longLived = request(NOW.plus(Duration.ofDays(31)));

        assertThatThrownBy(() -> RuntimeSuppressionService.validate(broad, NOW))
                .isInstanceOf(ApiException.class)
                .extracting(error -> ((ApiException) error).errorCode())
                .isEqualTo(ErrorCode.INVALID_INPUT);
        assertThatThrownBy(() -> RuntimeSuppressionService.validate(longLived, NOW))
                .isInstanceOf(ApiException.class)
                .extracting(error -> ((ApiException) error).errorCode())
                .isEqualTo(ErrorCode.INVALID_INPUT);
    }

    @Test
    void rejectsReusedIdempotencyKeyWithDifferentPayload() {
        RuntimeSuppressionRepository repository = mock(RuntimeSuppressionRepository.class);
        RuntimeSuppressionService service = new RuntimeSuppressionService(repository);
        when(repository.adminUserId("admin")).thenReturn(Optional.of(1L));
        when(repository.ruleExists("RUN-003")).thenReturn(true);
        when(repository.findByIdempotency(1L, "suppression-request-1"))
                .thenReturn(Optional.of(new IdempotentSuppression(9L, "different-digest")));

        assertThatThrownBy(() -> service.create("admin", request(Instant.now().plus(Duration.ofDays(7)))))
                .isInstanceOf(ApiException.class)
                .extracting(error -> ((ApiException) error).errorCode())
                .isEqualTo(ErrorCode.CONFLICT);
    }

    @Test
    void revokesWithOptimisticVersionCheck() {
        RuntimeSuppressionRepository repository = mock(RuntimeSuppressionRepository.class);
        RuntimeSuppressionService service = new RuntimeSuppressionService(repository);
        RuntimeSuppressionResponse revoked = response("REVOKED", 2);
        when(repository.adminUserId("admin")).thenReturn(Optional.of(1L));
        when(repository.findCurrentForUpdate(9L)).thenReturn(Optional.of(new CurrentSuppression(1, false)));
        when(repository.revoke(9L, 1L, 1, "approved activity ended")).thenReturn(1);
        when(repository.find(9L)).thenReturn(Optional.of(revoked));

        assertThat(service.revoke("admin", 9L,
                new RuntimeSuppressionRevokeRequest(1, "approved activity ended"))).isEqualTo(revoked);
        verify(repository).revoke(9L, 1L, 1, "approved activity ended");
    }

    private static RuntimeSuppressionCreateRequest request(Instant expiresAt) {
        return new RuntimeSuppressionCreateRequest(
                "RUN-003", "logssey-prod", "reused", "reused-api", "/app/reused-api",
                "/var/run/secrets/kubernetes.io/serviceaccount/", "OPEN",
                "APPROVED_OPERATION", "CHANGE:RUNTIME-100", "approved platform token access",
                expiresAt, "suppression-request-1");
    }

    private static RuntimeSuppressionResponse response(String status, long version) {
        return new RuntimeSuppressionResponse(
                9, "RUN-003", "logssey-prod", "reused", "reused-api", "/app/reused-api",
                "/var/run/secrets/kubernetes.io/serviceaccount/", "OPEN", "APPROVED_OPERATION",
                "CHANGE:RUNTIME-100", "approved platform token access", 1,
                NOW.toString(), NOW.plus(Duration.ofDays(7)).toString(), 1L, NOW.plusSeconds(60).toString(),
                "approved activity ended", status, version);
    }
}
